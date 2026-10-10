//! Local scan admission, terminal settlement and exact assessment head commits.

use super::*;

impl StateStore {
    pub(in crate::commands::maintain) fn reserve_local_assessment_source(
        &self,
        plan: &aos_assessment_runtime::provider::ProviderWorkPlanV1,
        now: &Timestamp,
    ) -> Result<()> {
        self.with_repository_lock(|| {
            let mut journal = self.local_journal()?;
            let mut receipt = self.local_receipt(&journal, &plan.claim.scan_id)?;
            anyhow::ensure!(
                receipt.state == ScanState::Running
                    && journal.is_current(&receipt)
                    && plan.claim.generation == receipt.generation
                    && plan.claim.inventory_revision == receipt.request.inventory_revision
                    && plan.authorization_partition == receipt.request.authorization_partition
                    && plan.claim.request_digest == receipt.request_digest
                    && plan.inventory_digest == receipt.request.inventory_digest
                    && plan.policy_digest == receipt.request.policy_digest,
                "local source work differs from current scan authority"
            );
            let usage = receipt.usage.consume(
                &ScanUsage {
                    provider_requests: plan.budget_reservation.requests,
                    tasks: 1,
                    normalized_bytes: 0,
                },
                &receipt.request.limits,
            )?;
            // Cancellation and request-wide usage share this repository lock.
            // The host-wide quota write precedes physical work; an index-write
            // failure conservatively loses allowance and cannot issue a call.
            self.claim_assessment_source(plan, now)?;
            receipt.usage = usage;
            receipt.resource_version = receipt
                .resource_version
                .checked_add(1)
                .filter(|revision| *revision <= MAX_LOCAL_REVISION)
                .context("local scan revision is exhausted")?;
            self.retain_local_receipt(&mut journal, &receipt)?;
            self.write_local_journal(&journal)
        })
    }

    pub(in crate::commands::maintain) fn consume_local_assessment_bytes(
        &self,
        scan_id: &str,
        bytes: u64,
    ) -> Result<()> {
        self.with_repository_lock(|| {
            let mut journal = self.local_journal()?;
            let mut receipt = self.local_receipt(&journal, scan_id)?;
            anyhow::ensure!(
                matches!(receipt.state, ScanState::Running | ScanState::Cancelling),
                "local assessment bytes cannot mutate terminal work"
            );
            receipt.usage = receipt.usage.consume(
                &ScanUsage {
                    normalized_bytes: bytes,
                    ..Default::default()
                },
                &receipt.request.limits,
            )?;
            receipt.resource_version = receipt
                .resource_version
                .checked_add(1)
                .filter(|revision| *revision <= MAX_LOCAL_REVISION)
                .context("local scan revision is exhausted")?;
            self.retain_local_receipt(&mut journal, &receipt)?;
            self.write_local_journal(&journal)
        })
    }

    pub(in crate::commands::maintain) fn recover_local_assessment_scans(
        &self,
        limit: usize,
    ) -> Result<Vec<ScanReceiptV1>> {
        anyhow::ensure!(
            (1..=100).contains(&limit),
            "local recovery exceeds its operation bound"
        );
        self.with_repository_lock(|| {
            let mut journal = self.local_journal()?;
            let candidates = journal
                .receipts
                .iter()
                .filter(|(_, reference)| !reference.state.is_terminal())
                .take(limit)
                .map(|(scan_id, _)| scan_id.clone())
                .collect::<Vec<_>>();
            let mut recovered = Vec::new();
            for scan_id in candidates {
                // Admission holds this per-operation lock before publishing
                // the receipt, including while waiting for the provider lane.
                let lease = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(
                        self.repository
                            .join("operation-locks")
                            .join(format!("{scan_id}.lock")),
                    )?;
                match rustix::fs::flock(
                    &lease,
                    rustix::fs::FlockOperation::NonBlockingLockExclusive,
                ) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::WOULDBLOCK => continue,
                    Err(error) => return Err(error.into()),
                }
                let mut receipt = self.local_receipt(&journal, &scan_id)?;
                let state = match receipt.state {
                    ScanState::Cancelling => ScanState::Cancelled,
                    ScanState::Queued => ScanState::Superseded,
                    _ => ScanState::Failed,
                };
                receipt.failure_code = Some(
                    if state == ScanState::Cancelled {
                        "local-scan-cancelled"
                    } else {
                        "local-process-interrupted"
                    }
                    .into(),
                );
                self.transition_local_receipt(&mut journal, &mut receipt, state)?;
                recovered.push(receipt);
            }
            if !recovered.is_empty() {
                self.write_local_journal(&journal)?;
            }
            Ok(recovered)
        })
    }

    pub(in crate::commands::maintain) fn admit_local_assessment_scan(
        &self,
        scan_id: &str,
        data: &EvaluationData,
        subjects: Vec<String>,
        profiles: Vec<Profile>,
        freshness: FreshnessMode,
        idempotency_key: &str,
        now: Timestamp,
    ) -> Result<(ScanReceiptV1, bool)> {
        validate_scan_id(scan_id)?;
        self.with_repository_lock(|| {
            let mut journal = self.local_journal()?;
            let inventory_digest = data.inventory.digest()?;
            let inventory_revision = if journal.inventory_digest == Some(inventory_digest) {
                journal.inventory_revision
            } else {
                journal
                    .inventory_revision
                    .checked_add(1)
                    .filter(|revision| *revision <= MAX_LOCAL_REVISION)
                    .context("local inventory revision is exhausted")?
            };
            let request = ScanRequestV1 {
                schema: SCAN_REQUEST_V1.into(),
                resource_scope: self.local_assessment_scope()?,
                authorization_partition: format!(
                    "local-{}",
                    Sha256Digest::of_bytes(self.root.as_os_str().as_encoded_bytes())
                ),
                inventory_revision,
                inventory_digest,
                policy_digest: data.policy.digest()?,
                subjects,
                profiles,
                freshness,
                trigger: "manual".into(),
                actor_ref: format!("local-user-{}", rustix::process::getuid().as_raw()),
                idempotency_key: idempotency_key.into(),
                limits: ScanLimits::default(),
            };
            let request_digest = request.digest()?;
            let key =
                Sha256Digest::separated("aos.local-assessment-idempotency/v1", idempotency_key)
                    .hex();
            if let Some(previous) = journal.idempotency.get(&key) {
                let receipt = self.local_receipt(&journal, previous)?;
                anyhow::ensure!(
                    receipt.request_digest == request_digest,
                    "local scan idempotency key already names a different frozen request"
                );
                return Ok((receipt, false));
            }
            anyhow::ensure!(
                journal.receipts.len() < MAX_LOCAL_SCANS && !journal.receipts.contains_key(scan_id),
                "local assessment scan retention is exhausted or identity is already consumed"
            );
            self.upgrade_local_profiles(&mut journal)?;
            if journal.inventory_digest != Some(inventory_digest)
                || journal.policy_digest != Some(request.policy_digest)
            {
                journal.profiles.clear();
            }
            let generation = journal
                .generation
                .checked_add(1)
                .filter(|generation| *generation <= MAX_LOCAL_REVISION)
                .context("local scan generation is exhausted")?;
            let receipt = ScanReceiptV1 {
                schema: "aos.assessment-scan-receipt/v1".into(),
                scan_id: scan_id.into(),
                request,
                request_digest,
                generation,
                state: ScanState::Queued,
                admission_complete: true,
                usage: ScanUsage::default(),
                created_at: now,
                resource_version: 1,
                assessment_digest: None,
                failure_code: None,
            };
            journal.generation = generation;
            journal.inventory_revision = inventory_revision;
            journal.inventory_digest = Some(inventory_digest);
            journal.policy_digest = Some(receipt.request.policy_digest);
            journal.idempotency.insert(key, scan_id.into());
            self.retain_local_receipt(&mut journal, &receipt)?;
            journal.desire_profiles(&receipt)?;
            let directory = self.assessment_directory()?;
            write_immutable(
                &directory,
                &format!("inventory-{}.json", inventory_digest.hex()),
                &data.inventory,
            )?;
            write_immutable(
                &directory,
                &format!("policy-{}.json", receipt.request.policy_digest.hex()),
                &data.policy,
            )?;
            self.write_local_journal(&journal)?;
            Ok((receipt, true))
        })
    }

    pub(in crate::commands::maintain) fn start_local_assessment_scan(
        &self,
        scan_id: &str,
    ) -> Result<ScanReceiptV1> {
        self.with_repository_lock(|| {
            let mut journal = self.local_journal()?;
            let mut receipt = self.local_receipt(&journal, scan_id)?;
            if receipt.state == ScanState::Cancelling {
                receipt.failure_code = Some("local-scan-cancelled".into());
                self.transition_local_receipt(&mut journal, &mut receipt, ScanState::Cancelled)?;
            } else if !journal.is_current(&receipt) {
                receipt.failure_code = Some("local-scan-superseded".into());
                self.transition_local_receipt(&mut journal, &mut receipt, ScanState::Superseded)?;
            } else {
                self.transition_local_receipt(&mut journal, &mut receipt, ScanState::Running)?;
            }
            self.write_local_journal(&journal)?;
            Ok(receipt)
        })
    }

    pub(in crate::commands::maintain) fn fail_local_assessment_scan(
        &self,
        scan_id: &str,
        code: &str,
    ) -> Result<ScanReceiptV1> {
        self.with_repository_lock(|| {
            let mut journal = self.local_journal()?;
            let mut receipt = self.local_receipt(&journal, scan_id)?;
            if receipt.state.is_terminal() {
                return Ok(receipt);
            }
            let (state, failure) = match receipt.state {
                ScanState::Cancelling => (ScanState::Cancelled, "local-scan-cancelled"),
                _ if !journal.is_current(&receipt) => {
                    (ScanState::Superseded, "local-scan-superseded")
                }
                ScanState::Queued => (ScanState::Superseded, code),
                _ => (ScanState::Failed, code),
            };
            receipt.failure_code = Some(failure.into());
            self.transition_local_receipt(&mut journal, &mut receipt, state)?;
            self.write_local_journal(&journal)?;
            Ok(receipt)
        })
    }

    pub(in crate::commands::maintain) fn commit_local_assessment_scan(
        &self,
        scan_id: &str,
        input: &ScanInputV1,
        data: &EvaluationData,
        result: &PackageAssessmentV1,
        usage: &ScanUsage,
    ) -> Result<ScanReceiptV1> {
        let frozen = data.freeze_selected(
            input.profiles.clone(),
            input.subject_refs.clone(),
            input.evaluated_at.clone(),
        )?;
        anyhow::ensure!(
            &frozen == input && result.input_digest == input.digest()?,
            "local assessment differs from its frozen evidence closure"
        );
        let assessment_digest = result.digest()?;
        let closure_digest = Sha256Digest::of_canonical("aos.local-assessment-closure/v1", data)?;
        self.with_repository_lock(|| {
            let mut journal = self.local_journal()?;
            let mut receipt = self.local_receipt(&journal, scan_id)?;
            if receipt.state.is_terminal() {
                anyhow::ensure!(
                    receipt.assessment_digest == Some(assessment_digest),
                    "local scan already has a different terminal receipt"
                );
                return Ok(receipt);
            }
            if receipt.state == ScanState::Cancelling {
                receipt.failure_code = Some("local-scan-cancelled".into());
                self.transition_local_receipt(&mut journal, &mut receipt, ScanState::Cancelled)?;
                self.write_local_journal(&journal)?;
                return Ok(receipt);
            }
            anyhow::ensure!(
                receipt.state == ScanState::Running
                    && input.inventory_digest == receipt.request.inventory_digest
                    && input.policy_digest == receipt.request.policy_digest
                    && input.subject_refs == receipt.request.subjects
                    && input.profiles == receipt.request.profiles,
                "local assessment commit differs from its admitted request"
            );
            if !journal.is_current(&receipt) {
                receipt.failure_code = Some("local-scan-superseded".into());
                self.transition_local_receipt(&mut journal, &mut receipt, ScanState::Superseded)?;
                self.write_local_journal(&journal)?;
                return Ok(receipt);
            }
            anyhow::ensure!(
                usage.provider_requests >= receipt.usage.provider_requests
                    && usage.tasks >= receipt.usage.tasks
                    && usage.normalized_bytes >= receipt.usage.normalized_bytes,
                "local assessment commit cannot refund usage"
            );
            receipt.usage = usage.clone();
            receipt.assessment_digest = Some(assessment_digest);
            let directory = self.assessment_directory()?;
            write_immutable(
                &directory,
                &format!("{}.json", assessment_digest.hex()),
                result,
            )?;
            write_immutable(
                &directory,
                &format!("data-{}.json", closure_digest.hex()),
                data,
            )?;
            write_immutable(
                &directory,
                &format!("input-{}.json", input.digest()?.hex()),
                input,
            )?;
            let state = if result.coverage == aos_assessment::security::CoverageState::Complete {
                ScanState::Succeeded
            } else {
                ScanState::Partial
            };
            self.transition_local_receipt(&mut journal, &mut receipt, state)?;
            let head = LocalHead {
                scan_id: scan_id.into(),
                assessment_digest,
                closure_digest,
                input_digest: input.digest()?,
            };
            for subject in &receipt.request.subjects {
                for profile in &receipt.request.profiles {
                    journal
                        .profiles
                        .get_mut(&profile_key(subject, *profile))
                        .context("committed local profile is absent")?
                        .committed = Some(head.clone());
                }
            }
            let replace_last = match &journal.head {
                Some(previous) => {
                    self.local_receipt(&journal, &previous.scan_id)?.generation < receipt.generation
                }
                None => true,
            };
            if replace_last {
                journal.head = Some(head);
            }
            self.write_local_journal(&journal)?;
            Ok(receipt)
        })
    }

    pub(in crate::commands::maintain) fn local_committed_assessment_closure(
        &self,
    ) -> Result<Option<EvaluationData>> {
        let journal = self.local_journal()?;
        let Some(head) = &journal.head else {
            return Ok(None);
        };
        self.local_head_evaluation(&journal, head)
            .map(|(data, _, _, _)| Some(data))
    }

    pub(super) fn local_head_evaluation(
        &self,
        journal: &LocalJournal,
        head: &LocalHead,
    ) -> Result<(
        EvaluationData,
        ScanInputV1,
        PackageAssessmentV1,
        ScanReceiptV1,
    )> {
        let receipt = self.local_receipt(&journal, &head.scan_id)?;
        anyhow::ensure!(
            receipt.assessment_digest == Some(head.assessment_digest),
            "local head differs from its terminal receipt"
        );
        let value = read_optional::<serde_json::Value>(
            &self
                .repository
                .join("assessments")
                .join(format!("data-{}.json", head.closure_digest.hex())),
            "local assessment closure",
        )?
        .context("local assessment closure custody is missing")?;
        let data = EvaluationData::from_slice(&serde_json::to_vec(&value)?)?;
        anyhow::ensure!(
            Sha256Digest::of_canonical("aos.local-assessment-closure/v1", &data)?
                == head.closure_digest,
            "local assessment closure differs from its immutable commitment"
        );
        let directory = self.repository.join("assessments");
        let input = read_optional::<serde_json::Value>(
            &directory.join(format!("input-{}.json", head.input_digest.hex())),
            "local assessment input",
        )?
        .context("local assessment input custody is missing")?;
        let input: ScanInputV1 = serde_json::from_value(input)?;
        input.validate()?;
        let result = read_optional::<serde_json::Value>(
            &directory.join(format!("{}.json", head.assessment_digest.hex())),
            "local assessment result",
        )?
        .context("local assessment result custody is missing")?;
        let result = PackageAssessmentV1::from_slice(&serde_json::to_vec(&result)?)?;
        anyhow::ensure!(
            input.digest()? == head.input_digest
                && result.digest()? == head.assessment_digest
                && result.input_digest == head.input_digest
                && input.inventory_digest == receipt.request.inventory_digest
                && input.policy_digest == receipt.request.policy_digest
                && input.subject_refs == receipt.request.subjects
                && input.profiles == receipt.request.profiles
                && data.freeze_selected(
                    input.profiles.clone(),
                    input.subject_refs.clone(),
                    input.evaluated_at.clone(),
                )? == input,
            "local assessment head custody differs from its frozen request"
        );
        Ok((data, input, result, receipt))
    }
}
