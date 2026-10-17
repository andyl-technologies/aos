//! Exact local assessment exports and separately retained reproduction imports.
//!
//! Successful scans write a receipt-bound sidecar before committing the journal.
//! Imports have their own protected index and never advance assessment heads.
//!
//! ```json
//! {"schema":"aos.local-assessment-evidence-ref/v1","receiptDigest":"sha256:...",
//!  "head":{"scanId":"00000000-0000-0000-0000-000000000001",
//!  "assessmentDigest":"sha256:...","closureDigest":"sha256:...","inputDigest":"sha256:..."}}
//! ```

use super::*;
use aos_assessment::bundle::{AssessmentBundleV1, BundleProfile};
use aos_assessment::reproduction::BundleReproductionV1;
use aos_contract::limits::JsonLimits;

const SMALL_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 64 * 1024,
    max_depth: 8,
    max_items: 1024,
    max_string_bytes: 128,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LocalEvidenceReference {
    schema: String,
    receipt_digest: Sha256Digest,
    head: LocalHead,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ImportedEvidenceIndex {
    schema: String,
    receipts: BTreeMap<Sha256Digest, Sha256Digest>,
}

impl StateStore {
    pub(super) fn retain_local_assessment_evidence(
        &self,
        receipt_digest: Sha256Digest,
        head: &LocalHead,
    ) -> Result<()> {
        let directory = self.assessment_directory()?.join("evidence-references");
        secure_directory(&directory)?;
        write_immutable(
            &directory,
            &format!("{}.json", receipt_digest.hex()),
            &LocalEvidenceReference {
                schema: "aos.local-assessment-evidence-ref/v1".into(),
                receipt_digest,
                head: head.clone(),
            },
        )
    }

    pub(in crate::commands::maintain) fn export_local_assessment_evidence(
        &self,
        digest: Sha256Digest,
    ) -> Result<AssessmentBundleV1> {
        self.with_repository_lock(|| {
            let journal = self.local_journal()?;
            let references = self.assessment_directory()?.join("evidence-references");
            secure_directory(&references)?;
            let mut charged = 0u64;
            for (scan_id, reference) in &journal.receipts {
                if !matches!(reference.state, ScanState::Succeeded | ScanState::Partial) {
                    continue;
                }
                let path = references.join(format!("{}.json", reference.digest.hex()));
                let Some(bytes) = read_evidence_file(&path, SMALL_LIMITS.max_bytes as u64)? else {
                    continue;
                };
                charged = charged
                    .checked_add(bytes.len() as u64)
                    .context("evidence reference read allowance overflow")?;
                anyhow::ensure!(
                    charged <= 16 * 1024 * 1024,
                    "evidence reference read allowance exceeded"
                );
                let value: serde_json::Value =
                    SMALL_LIMITS.decode(&bytes, "local evidence reference")?;
                let evidence: LocalEvidenceReference = serde_json::from_value(value)?;
                anyhow::ensure!(
                    evidence.schema == "aos.local-assessment-evidence-ref/v1"
                        && evidence.receipt_digest == reference.digest
                        && evidence.head.scan_id == *scan_id,
                    "local evidence reference differs from its committed receipt"
                );
                if evidence.head.assessment_digest == digest {
                    return self.bundle_from_local_head(&journal, &evidence.head);
                }
            }
            // Older journals retain exact global/profile heads without sidecars.
            // They can export those heads, never guess an unrelated old closure.
            for head in journal.head.iter().chain(
                journal
                    .profiles
                    .values()
                    .filter_map(|profile| profile.committed.as_ref()),
            ) {
                if head.assessment_digest == digest {
                    return self.bundle_from_local_head(&journal, head);
                }
            }
            bail!("exact local assessment evidence is unavailable")
        })
    }

    fn bundle_from_local_head(
        &self,
        journal: &LocalJournal,
        head: &LocalHead,
    ) -> Result<AssessmentBundleV1> {
        let reference = journal
            .receipts
            .get(&head.scan_id)
            .context("evidence receipt reference")?;
        let directory = self.repository.join("assessments");
        let mut charged = 0u64;
        for name in [
            format!("data-{}.json", head.closure_digest.hex()),
            format!("input-{}.json", head.input_digest.hex()),
            format!("{}.json", head.assessment_digest.hex()),
            format!("receipts/{}.json", reference.digest.hex()),
        ] {
            let metadata = directory.join(name).symlink_metadata()?;
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "export evidence is not regular immutable custody"
            );
            charged = charged
                .checked_add(metadata.len())
                .context("export custody byte allowance overflow")?;
            anyhow::ensure!(
                charged <= 64 * 1024 * 1024,
                "export custody byte allowance exceeded"
            );
        }
        let (data, input, result, _) = self.local_head_evaluation(journal, head)?;
        let bundle = AssessmentBundleV1::export(input, data, BundleProfile::Reference, vec![])?;
        anyhow::ensure!(
            bundle.assessment == result && bundle.assessment.digest()? == head.assessment_digest,
            "exported assessment does not reproduce its exact committed result"
        );
        Ok(bundle)
    }

    pub(in crate::commands::maintain) fn import_local_assessment_evidence(
        &self,
        bundle: &AssessmentBundleV1,
        now: Timestamp,
    ) -> Result<BundleReproductionV1> {
        let scope = self.local_assessment_scope()?;
        let reproduced = BundleReproductionV1::reproduce(bundle, &scope, now.clone())?;
        self.with_repository_lock(|| {
            let directory = self.assessment_directory()?.join("imports");
            secure_directory(&directory)?;
            let index_path = directory.join("index.json");
            let mut index = match read_evidence_file(&index_path, SMALL_LIMITS.max_bytes as u64)? {
                Some(bytes) => serde_json::from_value::<ImportedEvidenceIndex>(
                    SMALL_LIMITS.decode(&bytes, "local evidence import index")?,
                )?,
                None => ImportedEvidenceIndex {
                    schema: "aos.local-assessment-import-index/v1".into(),
                    receipts: BTreeMap::new(),
                },
            };
            anyhow::ensure!(
                index.schema == "aos.local-assessment-import-index/v1"
                    && index.receipts.len() <= 64,
                "local evidence import index exceeds its closed bounds"
            );
            let manifest = reproduced.bundle_manifest_digest;
            let bundle_path = directory.join(format!("bundle-{}.json", manifest.hex()));
            if let Some(expected) = index.receipts.get(&manifest) {
                let bytes = read_evidence_file(
                    &directory.join(format!("receipt-{}.json", expected.hex())),
                    64 * 1024,
                )?
                .context("import receipt custody is missing")?;
                let receipt = BundleReproductionV1::from_slice(&bytes)?;
                anyhow::ensure!(
                    receipt.digest()? == *expected,
                    "import receipt differs from its immutable identity"
                );
                let retained = read_evidence_file(&bundle_path, 16 * 1024 * 1024)?
                    .context("import bundle custody is missing")?;
                let retained = AssessmentBundleV1::from_slice(&retained)?;
                receipt.verify_for(&retained, &scope, &now)?;
                receipt.verify_for(bundle, &scope, &now)?;
                return Ok(receipt);
            }
            anyhow::ensure!(
                index.receipts.len() < 64,
                "local evidence import allowance is exhausted"
            );
            if let Some(bytes) = read_evidence_file(&bundle_path, 16 * 1024 * 1024)? {
                anyhow::ensure!(
                    AssessmentBundleV1::from_slice(&bytes)?.verify()? == manifest,
                    "retained import bundle differs from its manifest"
                );
            } else {
                // Container bytes are not the identity: retain the first valid
                // encoding, and compare manifests on equivalent reimports.
                write_immutable_bytes(
                    &directory,
                    &format!("bundle-{}.json", manifest.hex()),
                    &bundle.encoded()?,
                )?;
            }
            let digest = reproduced.digest()?;
            write_immutable_bytes(
                &directory,
                &format!("receipt-{}.json", digest.hex()),
                &reproduced.to_bytes()?,
            )?;
            index.receipts.insert(manifest, digest);
            atomic_write(&directory, "index.json", &index)?;
            Ok(reproduced)
        })
    }
}

fn read_evidence_file(path: &std::path::Path, limit: u64) -> Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "evidence custody is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= limit,
        "evidence custody grew beyond its byte allowance"
    );
    Ok(Some(bytes))
}
