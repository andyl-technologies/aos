//! Bounded cache reuse across independent committed local profile heads.

use aos_assessment_runtime::cache::merge_committed_evidence;

use super::*;

const MAX_CACHE_CUSTODY_BYTES: u64 = 64 * 1024 * 1024;

impl StateStore {
    pub(in crate::commands::maintain) fn local_cached_assessment_closure(
        &self,
    ) -> Result<Option<EvaluationData>> {
        self.with_repository_lock(|| {
            let journal = self.local_journal()?;
            let Some(global) = &journal.head else {
                anyhow::ensure!(
                    journal
                        .profiles
                        .values()
                        .all(|slot| slot.committed.is_none()),
                    "local cache has profile heads without a published operation"
                );
                return Ok(None);
            };
            let mut bytes = 0;
            self.charge_local_cache_custody(&journal, global, &mut bytes)?;
            let (original, _, _, global_receipt) = self.local_head_evaluation(&journal, global)?;
            // An inventory change may retain historical first-observation data.
            // The caller checks scope before reusing any source bindings.
            let inventory_digest = original.inventory.digest()?;
            let policy_digest = original.policy.digest()?;
            if journal.schema == "aos.local-assessment-journal/v1"
                || journal.inventory_digest != Some(inventory_digest)
                || journal.policy_digest != Some(policy_digest)
            {
                return Ok(Some(original));
            }
            let mut heads = BTreeMap::from([(global.scan_id.clone(), (global.clone(), vec![]))]);
            for slot in journal.profiles.values() {
                let Some(head) = &slot.committed else {
                    continue;
                };
                let entry = heads
                    .entry(head.scan_id.clone())
                    .or_insert_with(|| (head.clone(), vec![]));
                anyhow::ensure!(
                    entry.0 == *head,
                    "local cache has conflicting immutable head references"
                );
                entry.1.push((slot.subject_ref.clone(), slot.profile));
            }
            let mut ordered = Vec::new();
            for (head, slots) in heads.into_values() {
                let receipt = if head.scan_id == global.scan_id {
                    global_receipt.clone()
                } else {
                    self.charge_local_cache_custody(&journal, &head, &mut bytes)?;
                    self.local_receipt(&journal, &head.scan_id)?
                };
                anyhow::ensure!(
                    receipt.request.inventory_digest == inventory_digest
                        && receipt.request.policy_digest == policy_digest
                        && receipt.request.inventory_revision == journal.inventory_revision,
                    "local committed cache differs from the current inventory or policy"
                );
                for (subject, profile) in slots {
                    anyhow::ensure!(
                        receipt.request.subjects.contains(&subject)
                            && receipt.request.profiles.contains(&profile),
                        "local committed cache differs from its subject/profile slot"
                    );
                }
                ordered.push((receipt.generation, head));
            }
            ordered
                .sort_by(|left, right| (left.0, &left.1.scan_id).cmp(&(right.0, &right.1.scan_id)));
            let mut data = original.clone();
            data.upstream.clear();
            data.history.clear();
            data.advisories.clear();
            data.advisory_snapshot = None;
            for (_, head) in ordered {
                let retained = if head.scan_id == global.scan_id {
                    original.clone()
                } else {
                    self.local_head_evaluation(&journal, &head)?.0
                };
                merge_committed_evidence(&mut data, retained)?;
                anyhow::ensure!(
                    canonical::to_vec(&data)?.len() <= 16 * 1024 * 1024,
                    "local committed cache accumulator exceeds its byte allowance"
                );
            }
            Ok(Some(data))
        })
    }

    fn charge_local_cache_custody(
        &self,
        journal: &LocalJournal,
        head: &LocalHead,
        consumed: &mut u64,
    ) -> Result<()> {
        let reference = journal
            .receipts
            .get(&head.scan_id)
            .context("local cache receipt reference")?;
        let directory = self.repository.join("assessments");
        for name in [
            format!("data-{}.json", head.closure_digest.hex()),
            format!("input-{}.json", head.input_digest.hex()),
            format!("{}.json", head.assessment_digest.hex()),
            format!("receipts/{}.json", reference.digest.hex()),
        ] {
            let metadata = directory.join(name).symlink_metadata()?;
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "local cache custody is not a regular file"
            );
            *consumed = consumed
                .checked_add(metadata.len())
                .context("local cache custody size overflows")?;
            anyhow::ensure!(
                *consumed <= MAX_CACHE_CUSTODY_BYTES,
                "local cache custody exceeds its byte allowance"
            );
        }
        Ok(())
    }
}
