//! Bounded local projection of independent shared subject/profile status.

use aos_assessment::input::AssessmentPolicyV1;
use aos_assessment::scan_inventory::{InventorySubject, ScanInventoryV1};
use aos_assessment_runtime::application::{
    AssessmentStatusV1, ProfileStatus, StatusQueryV1, SubjectStatus,
};
use aos_assessment_runtime::status::profile_freshness_deadline;

use super::*;

const MAX_STATUS_CUSTODY_BYTES: u64 = 256 * 1024 * 1024;

type LocalEvaluation = (
    EvaluationData,
    ScanInputV1,
    PackageAssessmentV1,
    ScanReceiptV1,
);

#[derive(Default)]
struct StatusCustody {
    bytes: u64,
    evaluations: BTreeMap<String, (LocalHead, LocalEvaluation)>,
}

impl StateStore {
    pub(in crate::commands::maintain) fn local_assessment_status(
        &self,
        query: &StatusQueryV1,
        now: Timestamp,
    ) -> Result<AssessmentStatusV1> {
        query.validate()?;
        self.with_repository_lock(|| self.local_status_page(query, now))
    }

    fn local_status_page(
        &self,
        query: &StatusQueryV1,
        now: Timestamp,
    ) -> Result<AssessmentStatusV1> {
        let journal = self.local_journal()?;
        anyhow::ensure!(
            journal.schema == "aos.local-assessment-journal/v2",
            "run a new profiled scan to upgrade the legacy journal before reading shared status"
        );
        let inventory_digest = journal
            .inventory_digest
            .context("no local inventory has been admitted")?;
        let policy_digest = journal
            .policy_digest
            .context("no local policy has been admitted")?;
        anyhow::ensure!(
            query
                .inventory_digest
                .is_none_or(|digest| digest == inventory_digest)
                && query
                    .policy_digest
                    .is_none_or(|digest| digest == policy_digest),
            "local status inventory or policy changed; restart pagination"
        );

        let directory = self.repository.join("assessments");
        let inventory: ScanInventoryV1 = read_optional(
            &directory.join(format!("inventory-{}.json", inventory_digest.hex())),
            "immutable local inventory",
        )?
        .context("local inventory custody is missing")?;
        let policy: AssessmentPolicyV1 = read_optional(
            &directory.join(format!("policy-{}.json", policy_digest.hex())),
            "immutable local policy",
        )?
        .context("local policy custody is missing")?;
        anyhow::ensure!(
            inventory.digest()? == inventory_digest && policy.digest()? == policy_digest,
            "local inventory or policy differs from its immutable commitment"
        );

        let selected = inventory
            .subjects
            .iter()
            .filter(|subject| {
                query
                    .after_subject
                    .as_ref()
                    .is_none_or(|after| subject.subject_ref > *after)
            })
            .take(query.limit as usize + 1)
            .collect::<Vec<_>>();
        let mut custody = StatusCustody::default();
        let mut subjects = Vec::with_capacity(query.limit as usize);
        for subject in selected.iter().take(query.limit as usize) {
            let profiles = query
                .profiles
                .iter()
                .map(|profile| {
                    self.local_status_profile(&journal, subject, *profile, &now, &mut custody)
                })
                .collect::<Result<Vec<_>>>()?;
            subjects.push(SubjectStatus {
                subject_ref: subject.subject_ref.clone(),
                package_coordinate: subject.package_coordinate.clone(),
                version: subject.version.clone(),
                platform: subject.platform.clone(),
                output: subject.output.clone(),
                profiles,
            });
        }
        let next_subject = if selected.len() > query.limit as usize {
            subjects.last().map(|subject| subject.subject_ref.clone())
        } else {
            None
        };
        let status = AssessmentStatusV1 {
            schema: "aos.assessment-status/v1".into(),
            resource_scope: self.local_assessment_scope()?,
            inventory_digest,
            inventory_revision: journal.inventory_revision,
            policy_digest,
            as_of: now,
            source_status: Vec::new(),
            subjects,
            next_subject,
        };
        status.to_bytes()?;
        Ok(status)
    }

    fn local_status_profile(
        &self,
        journal: &LocalJournal,
        subject: &InventorySubject,
        profile: Profile,
        now: &Timestamp,
        custody: &mut StatusCustody,
    ) -> Result<ProfileStatus> {
        let mut state = ProfileStatus {
            profile,
            desired_generation: 0,
            committed_generation: 0,
            assessment_digest: None,
            input_digest: None,
            validated_until: None,
            fresh: false,
            pending: false,
        };
        let Some(slot) = journal
            .profiles
            .get(&profile_key(&subject.subject_ref, profile))
        else {
            return Ok(state);
        };
        let desired = self.local_receipt(journal, &slot.desired_scan_id)?;
        anyhow::ensure!(
            desired.generation == slot.desired_generation
                && desired.request.inventory_revision == journal.inventory_revision
                && Some(desired.request.inventory_digest) == journal.inventory_digest
                && Some(desired.request.policy_digest) == journal.policy_digest
                && desired.request.subjects.contains(&subject.subject_ref)
                && desired.request.profiles.contains(&profile),
            "local desired profile differs from its retained request"
        );
        state.desired_generation = desired.generation;
        if let Some(head) = &slot.committed {
            self.load_status_custody(journal, head, custody)?;
            let (_, (data, input, result, committed)) = custody
                .evaluations
                .get(&head.scan_id)
                .context("local profile evaluation is absent")?;
            anyhow::ensure!(
                committed.generation <= desired.generation
                    && committed.request.inventory_revision == journal.inventory_revision
                    && Some(input.inventory_digest) == journal.inventory_digest
                    && Some(input.policy_digest) == journal.policy_digest
                    && input.subject_refs.contains(&subject.subject_ref)
                    && input.profiles.contains(&profile),
                "local committed profile differs from its exact indexed custody"
            );
            let coverage = result
                .subject_results
                .iter()
                .find(|result| result.subject_ref == subject.subject_ref)
                .and_then(|result| {
                    result
                        .coverage
                        .iter()
                        .find(|coverage| coverage.profile == profile)
                })
                .context("local committed profile lacks exact subject coverage")?;
            state.committed_generation = committed.generation;
            state.assessment_digest = Some(head.assessment_digest);
            state.input_digest = Some(head.input_digest);
            state.validated_until = profile_freshness_deadline(input, data, coverage)?;
            state.fresh = state
                .validated_until
                .as_ref()
                .is_some_and(|deadline| now < deadline);
        }
        state.pending = desired.generation > state.committed_generation
            && !desired.state.is_terminal()
            && journal.is_current(&desired);
        Ok(state)
    }

    fn load_status_custody(
        &self,
        journal: &LocalJournal,
        head: &LocalHead,
        custody: &mut StatusCustody,
    ) -> Result<()> {
        if let Some((verified, _)) = custody.evaluations.get(&head.scan_id) {
            anyhow::ensure!(
                verified == head,
                "local profile heads disagree about immutable custody"
            );
            return Ok(());
        }
        let reference = journal
            .receipts
            .get(&head.scan_id)
            .context("committed receipt reference")?;
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
                "local profile custody is not a regular file"
            );
            custody.bytes = custody
                .bytes
                .checked_add(metadata.len())
                .context("local status custody size overflows")?;
            anyhow::ensure!(
                custody.bytes <= MAX_STATUS_CUSTODY_BYTES,
                "local status custody limit exceeded; select fewer profiles or reduce the page limit"
            );
        }
        // Verify a full closure once per immutable head. Repeated subjects and
        // profiles reuse that proof without retaining an unbounded set of bodies.
        custody.evaluations.insert(
            head.scan_id.clone(),
            (head.clone(), self.local_head_evaluation(journal, head)?),
        );
        Ok(())
    }
}
