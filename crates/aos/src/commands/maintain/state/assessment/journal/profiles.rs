//! Independent desired generations and committed profile heads in journal v2.
//!
//! An index update commits every slot selected by one scan together. Inventory
//! or policy replacement clears current slots; old immutable custody is retained.
//! Migration preserves only the head that v1 actually published, rather than
//! treating every historical terminal result as a previously current profile.

use super::*;

const MAX_PROFILE_HEADS: usize = 4096 * 3;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct LocalProfileHead {
    pub(super) subject_ref: String,
    pub(super) profile: Profile,
    pub(super) desired_generation: u64,
    pub(super) desired_scan_id: String,
    pub(super) committed: Option<LocalHead>,
}

pub(super) fn profile_key(subject: &str, profile: Profile) -> String {
    // Length framing prevents ambiguous subject/profile concatenation. Profile
    // names are versioned enum values, independent of platform or display text.
    let name = match profile {
        Profile::Updates => "updates",
        Profile::Vulnerabilities => "vulnerabilities",
        Profile::LicenseSignals => "license-signals",
    };
    Sha256Digest::separated(
        "aos.local-assessment-profile-slot/v1",
        format!("{}:{subject}:{name}", subject.len()),
    )
    .hex()
}

impl LocalJournal {
    pub(super) fn validate_profile_heads(&self) -> Result<()> {
        anyhow::ensure!(
            self.profiles.len() <= MAX_PROFILE_HEADS
                && (self.schema != "aos.local-assessment-journal/v1" || self.profiles.is_empty()),
            "invalid local profile index schema or bounds"
        );
        for (key, head) in &self.profiles {
            anyhow::ensure!(
                *key == profile_key(&head.subject_ref, head.profile)
                    && !head.subject_ref.is_empty()
                    && head.subject_ref.len() <= 128
                    && !head.subject_ref.chars().any(char::is_control)
                    && head.desired_generation > 0
                    && head.desired_generation <= self.generation
                    && self.receipts.contains_key(&head.desired_scan_id),
                "local profile index has invalid desired authority"
            );
            if let Some(committed) = &head.committed {
                anyhow::ensure!(
                    self.receipts
                        .get(&committed.scan_id)
                        .is_some_and(|reference| {
                            matches!(reference.state, ScanState::Succeeded | ScanState::Partial)
                        }),
                    "local profile head lacks a retained completed receipt"
                );
            }
        }
        Ok(())
    }

    pub(super) fn desire_profiles(&mut self, receipt: &ScanReceiptV1) -> Result<()> {
        for subject in &receipt.request.subjects {
            for profile in &receipt.request.profiles {
                let slot = self
                    .profiles
                    .entry(profile_key(subject, *profile))
                    .or_insert_with(|| LocalProfileHead {
                        subject_ref: subject.clone(),
                        profile: *profile,
                        desired_generation: receipt.generation,
                        desired_scan_id: receipt.scan_id.clone(),
                        committed: None,
                    });
                slot.desired_generation = receipt.generation;
                slot.desired_scan_id = receipt.scan_id.clone();
            }
        }
        anyhow::ensure!(
            self.profiles.len() <= MAX_PROFILE_HEADS,
            "local profile index capacity exhausted"
        );
        Ok(())
    }
}

impl StateStore {
    pub(super) fn upgrade_local_profiles(&self, journal: &mut LocalJournal) -> Result<()> {
        if journal.schema != "aos.local-assessment-journal/v1" {
            return Ok(());
        }
        let head = journal.head.clone();
        let mut receipts = journal
            .receipts
            .keys()
            .map(|scan_id| self.local_receipt(journal, scan_id))
            .collect::<Result<Vec<_>>>()?;
        receipts.sort_by_key(|receipt| receipt.generation);
        for receipt in &receipts {
            if Some(receipt.request.inventory_digest) == journal.inventory_digest
                && Some(receipt.request.policy_digest) == journal.policy_digest
            {
                journal.desire_profiles(receipt)?;
            }
        }
        if let Some(head) = head {
            let receipt = self.local_receipt(journal, &head.scan_id)?;
            if Some(receipt.request.inventory_digest) == journal.inventory_digest
                && Some(receipt.request.policy_digest) == journal.policy_digest
            {
                for subject in &receipt.request.subjects {
                    for profile in &receipt.request.profiles {
                        journal
                            .profiles
                            .get_mut(&profile_key(subject, *profile))
                            .context("legacy committed profile is absent")?
                            .committed = Some(head.clone());
                    }
                }
            }
        }
        // A new admission superseded every active v1 operation under v1's global
        // generation rule. Preserve that rule at migration; do not resurrect an
        // old disjoint process by switching it to per-profile eligibility.
        for mut receipt in receipts
            .into_iter()
            .filter(|receipt| !receipt.state.is_terminal())
        {
            let (state, code) = if receipt.state == ScanState::Cancelling {
                (ScanState::Cancelled, "local-scan-cancelled")
            } else {
                (ScanState::Superseded, "local-journal-v2-migration")
            };
            receipt.failure_code = Some(code.into());
            self.transition_local_receipt(journal, &mut receipt, state)?;
        }
        journal.schema = "aos.local-assessment-journal/v2".into();
        Ok(())
    }
}
