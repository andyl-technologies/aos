//! Immutable local scan receipts and the atomic repository journal index.
//!
//! Individual receipt versions are content addressed. One protected index
//! commits their current references together with the selected assessment head;
//! a crash before that index write cannot publish half of a terminal operation.
//! Provider attempts remain independently accounted in the host-wide budget.
//!
//! ```json
//! {
//!   "schema": "aos.local-assessment-journal/v2",
//!   "generation": 0, "inventoryRevision": 0,
//!   "inventoryDigest": null, "policyDigest": null,
//!   "receipts": {}, "idempotency": {}, "head": null, "profiles": {}
//! }
//! ```

use aos_assessment::input::{FreshnessMode, Profile, ScanInputV1};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::application::ScanReceiptV1;
use aos_assessment_runtime::control::{
    ScanCancellationV1, ScanListQueryV1, ScanListV1, ScanSummary,
};
use aos_assessment_runtime::scan::{
    SCAN_REQUEST_V1, ScanLimits, ScanRequestV1, ScanState, ScanUsage,
};
use std::collections::BTreeSet;

use super::*;

mod operations;
mod profiles;
mod status;

use profiles::{LocalProfileHead, profile_key};

#[cfg(test)]
mod tests;

const MAX_LOCAL_SCANS: usize = 4096;
const MAX_LOCAL_REVISION: u64 = 9_007_199_254_740_991;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalJournal {
    schema: String,
    generation: u64,
    inventory_revision: u64,
    inventory_digest: Option<Sha256Digest>,
    policy_digest: Option<Sha256Digest>,
    receipts: BTreeMap<String, LocalReceiptReference>,
    idempotency: BTreeMap<String, String>,
    head: Option<LocalHead>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    profiles: BTreeMap<String, LocalProfileHead>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalReceiptReference {
    digest: Sha256Digest,
    state: ScanState,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalHead {
    scan_id: String,
    assessment_digest: Sha256Digest,
    closure_digest: Sha256Digest,
    input_digest: Sha256Digest,
}

impl Default for LocalJournal {
    fn default() -> Self {
        Self {
            schema: "aos.local-assessment-journal/v2".into(),
            generation: 0,
            inventory_revision: 0,
            inventory_digest: None,
            policy_digest: None,
            receipts: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            head: None,
            profiles: BTreeMap::new(),
        }
    }
}

impl LocalJournal {
    fn is_current(&self, receipt: &ScanReceiptV1) -> bool {
        !receipt.state.is_terminal()
            && self
                .receipts
                .get(&receipt.scan_id)
                .is_some_and(|reference| reference.state == receipt.state)
            && (if self.schema == "aos.local-assessment-journal/v1" {
                self.generation == receipt.generation
            } else {
                receipt.request.subjects.iter().all(|subject| {
                    receipt.request.profiles.iter().all(|profile| {
                        self.profiles
                            .get(&profile_key(subject, *profile))
                            .is_some_and(|head| {
                                head.desired_generation == receipt.generation
                                    && head.desired_scan_id == receipt.scan_id
                            })
                    })
                })
            })
            && self.inventory_revision == receipt.request.inventory_revision
            && self.inventory_digest == Some(receipt.request.inventory_digest)
            && self.policy_digest == Some(receipt.request.policy_digest)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            matches!(
                self.schema.as_str(),
                "aos.local-assessment-journal/v1" | "aos.local-assessment-journal/v2"
            ) && self.generation <= MAX_LOCAL_REVISION
                && self.inventory_revision <= MAX_LOCAL_REVISION
                && self.receipts.len() <= MAX_LOCAL_SCANS
                && self.idempotency.len() == self.receipts.len(),
            "invalid local assessment journal schema or bounds"
        );
        self.validate_profile_heads()?;
        anyhow::ensure!(
            self.inventory_digest.is_some() == (self.inventory_revision > 0)
                && self.policy_digest.is_some() == self.inventory_digest.is_some()
                && (self.generation > 0) == !self.receipts.is_empty(),
            "local assessment journal has inconsistent inventory generations"
        );
        for scan_id in self.receipts.keys() {
            validate_scan_id(scan_id)?;
        }
        for (key, scan_id) in &self.idempotency {
            anyhow::ensure!(
                key.len() == 64
                    && key.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && self.receipts.contains_key(scan_id),
                "local idempotency index has an invalid reference"
            );
        }
        anyhow::ensure!(
            self.idempotency.values().collect::<BTreeSet<_>>().len() == self.receipts.len(),
            "local idempotency index does not cover each scan exactly once"
        );
        if let Some(head) = &self.head {
            anyhow::ensure!(
                self.receipts.get(&head.scan_id).is_some_and(|reference| {
                    matches!(reference.state, ScanState::Succeeded | ScanState::Partial)
                }),
                "local assessment head has no completed retained scan"
            );
        }
        Ok(())
    }
}

fn validate_scan_id(scan_id: &str) -> Result<()> {
    anyhow::ensure!(
        uuid::Uuid::parse_str(scan_id)?.hyphenated().to_string() == scan_id,
        "local scan identity is not a canonical UUID"
    );
    Ok(())
}

impl StateStore {
    pub(in crate::commands::maintain) fn local_assessment_scope(&self) -> Result<String> {
        let identity = self
            .repository
            .file_name()
            .and_then(|name| name.to_str())
            .context("local assessment namespace has no identity")?;
        anyhow::ensure!(
            identity.len() == 64 && identity.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "local assessment namespace identity is invalid"
        );
        Ok(format!("local-{identity}"))
    }

    fn local_journal(&self) -> Result<LocalJournal> {
        let journal: LocalJournal = read_optional(
            &self.repository.join("assessments/journal.json"),
            "local assessment journal",
        )?
        .unwrap_or_default();
        journal.validate()?;
        Ok(journal)
    }

    fn write_local_journal(&self, journal: &LocalJournal) -> Result<()> {
        journal.validate()?;
        atomic_write(&self.assessment_directory()?, "journal.json", journal)
    }

    fn local_receipt(&self, journal: &LocalJournal, scan_id: &str) -> Result<ScanReceiptV1> {
        validate_scan_id(scan_id)?;
        let reference = journal
            .receipts
            .get(scan_id)
            .context("local assessment scan does not exist")?;
        let path = self
            .repository
            .join("assessments/receipts")
            .join(format!("{}.json", reference.digest.hex()));
        let bytes = read_optional::<serde_json::Value>(&path, "immutable local scan receipt")?
            .context("local assessment receipt custody is missing")?;
        let receipt = ScanReceiptV1::from_slice(&serde_json::to_vec(&bytes)?)?;
        anyhow::ensure!(
            receipt.scan_id == scan_id
                && receipt.request.resource_scope == self.local_assessment_scope()?
                && Sha256Digest::of_canonical("aos.local-scan-receipt/v1", &receipt)?
                    == reference.digest
                && receipt.state == reference.state,
            "local scan receipt differs from its exact journal commitment"
        );
        Ok(receipt)
    }

    fn retain_local_receipt(
        &self,
        journal: &mut LocalJournal,
        receipt: &ScanReceiptV1,
    ) -> Result<()> {
        receipt.to_bytes()?;
        validate_scan_id(&receipt.scan_id)?;
        let digest = Sha256Digest::of_canonical("aos.local-scan-receipt/v1", receipt)?;
        let directory = self.assessment_directory()?.join("receipts");
        secure_directory(&directory)?;
        write_immutable(&directory, &format!("{}.json", digest.hex()), receipt)?;
        journal.receipts.insert(
            receipt.scan_id.clone(),
            LocalReceiptReference {
                digest,
                state: receipt.state,
            },
        );
        Ok(())
    }

    fn transition_local_receipt(
        &self,
        journal: &mut LocalJournal,
        receipt: &mut ScanReceiptV1,
        state: ScanState,
    ) -> Result<()> {
        receipt.state = receipt.state.transition(state)?;
        receipt.resource_version = receipt
            .resource_version
            .checked_add(1)
            .filter(|revision| *revision <= MAX_LOCAL_REVISION)
            .context("local scan revision is exhausted")?;
        self.retain_local_receipt(journal, receipt)
    }

    pub(in crate::commands::maintain) fn inspect_local_assessment_scan(
        &self,
        scan_id: &str,
    ) -> Result<ScanReceiptV1> {
        // Immutable receipt files allow a complete read from one atomic index
        // snapshot without holding a controller lock or mutating operation state.
        self.local_receipt(&self.local_journal()?, scan_id)
    }

    pub(in crate::commands::maintain) fn list_local_assessment_scans(
        &self,
        query: &ScanListQueryV1,
        now: Timestamp,
    ) -> Result<ScanListV1> {
        ScanListQueryV1::from_slice(&serde_json::to_vec(query)?)?;
        let journal = self.local_journal()?;
        let ids = journal
            .receipts
            .keys()
            .filter(|scan_id| {
                query
                    .after_scan
                    .as_ref()
                    .is_none_or(|after| *scan_id > after)
            })
            .take(query.limit as usize + 1)
            .collect::<Vec<_>>();
        let mut scans = Vec::new();
        for id in ids.iter().take(query.limit as usize) {
            let receipt = self.local_receipt(&journal, id)?;
            scans.push(ScanSummary {
                scan_id: receipt.scan_id,
                request_digest: receipt.request_digest,
                state: receipt.state,
                generation: receipt.generation,
                resource_version: receipt.resource_version,
                created_at: receipt.created_at,
                assessment_digest: receipt.assessment_digest,
            });
        }
        let next_scan = (ids.len() > query.limit as usize)
            .then(|| scans.last().map(|scan| scan.scan_id.clone()))
            .flatten();
        let page = ScanListV1 {
            schema: "aos.assessment-scan-list/v1".into(),
            resource_scope: self.local_assessment_scope()?,
            as_of: now,
            scans,
            next_scan,
        };
        page.to_bytes()?;
        Ok(page)
    }

    pub(in crate::commands::maintain) fn require_local_assessment_running(
        &self,
        scan_id: &str,
    ) -> Result<()> {
        let journal = self.local_journal()?;
        let receipt = self.local_receipt(&journal, scan_id)?;
        anyhow::ensure!(
            receipt.state == ScanState::Running && journal.is_current(&receipt),
            "local assessment scan no longer has current execution authority"
        );
        Ok(())
    }

    pub(in crate::commands::maintain) fn cancel_local_assessment_scan(
        &self,
        cancellation: &ScanCancellationV1,
    ) -> Result<ScanReceiptV1> {
        ScanCancellationV1::from_slice(&serde_json::to_vec(cancellation)?)?;
        self.with_repository_lock(|| {
            let mut journal = self.local_journal()?;
            let mut receipt = self.local_receipt(&journal, &cancellation.scan_id)?;
            anyhow::ensure!(
                receipt.resource_version == cancellation.expected_revision
                    && matches!(receipt.state, ScanState::Queued | ScanState::Running),
                "local scan cancellation revision conflicts"
            );
            self.transition_local_receipt(&mut journal, &mut receipt, ScanState::Cancelling)?;
            self.write_local_journal(&journal)?;
            Ok(receipt)
        })
    }
}
