//! Owns fixed Cache Git comparison, denial fencing and full native catalogue folds.
//!
//! The same real Broker credential owner and private Cache writers remain
//! borrowed at every existing pre/post frontier; signed DATA grants no effect.

use super::*;

impl CacheResidentInitializationV1 {
    /// Bookends the selected component with the same actual credential owner.
    ///
    /// # Errors
    /// Permanently retains credential-change or original-owner failure; the
    /// returned success is component readback DATA, never admission authority.
    #[cfg(target_os = "linux")]
    pub fn recheck_git_coverage(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.complete = false;
            self.first_failure.get_or_insert(cause);
            return Err(CacheResidentUnavailableV1);
        }
        let returned = self.compare_fixed_git_coverage_catalog(owner, original_inputs)
            .and_then(|()| self.recheck(owner));
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.complete = false;
            self.postcheck.get_or_insert(cause);
        }
        returned?;
        if self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Compares the genuinely empty logical and physical Cache cohort.
    ///
    /// The complete existing replay supplies every partition, including
    /// checkpoint-only state. Signed catalog bytes alone, absent projects and
    /// absent current keys never prove emptiness. This result is comparison
    /// DATA, not enrollment, a complete account, funding or an effect permit.
    ///
    /// # Errors
    /// Permanently retains changed originals, unknown or historical tenant
    /// state, disjoint quotas, physical debt or failed independent bookends.
    #[cfg(target_os = "linux")]
    pub fn audit_empty_git_coverage_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &crate::physical::DormantCacheOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.recheck_git_coverage(owner, original_inputs)?;
        let project = match self.coverage_inputs {
            Some(inputs) => inputs.project,
            None => {
                self.complete = false;
                self.first_failure.get_or_insert(InitializationCauseV1::CoverageInputs);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let inventories = self.existing_pin_inventories(owner)?;
        let residual = inventories.is_empty() || inventories.iter().any(|inventory| {
            inventory.authority_poisoned
                || !inventory.work.is_empty()
                || !inventory.reconstructed.is_empty()
                || !inventory.family_heads.is_empty()
                || !inventory.global.watermarks.is_empty()
                || !inventory.global.idempotency.is_empty()
                || inventory.global.pin_floor.is_some()
                || inventory.global.idempotency_floor.is_some()
                || !inventory.global.handoffs.is_empty()
                || !inventory.global.lookups.is_empty()
                || inventory.global.poison.is_some()
                || inventory.global.project_quotas.len() != 1
                || inventory.global.project_quotas.iter().any(|quota| {
                    quota.project != project
                        || quota.partition != inventory.global.node_quota.partition
                })
        });
        self.complete = false;

        let returned = (|| {
            if residual {
                return Err(InitializationCauseV1::CoverageResidual);
            }
            let evidence = self.targets.evidence.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(InitializationCauseV1::Evidence)?;
            let inventories = self.pin_inventory.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(InitializationCauseV1::Mutation)?;
            if inventories.len() != evidence.len() {
                return Err(InitializationCauseV1::CoverageResidual);
            }
            for item in evidence {
                if item.prior_typed_checkpoint.is_some() {
                    return Err(InitializationCauseV1::CoverageResidual);
                }
                validate_genesis_checkpoint(
                    item.partition, &item.typed_checkpoint, item.floor,
                    CacheRecoveryLimitsV1::default(),
                )?;
                if inventories.iter().filter(|inventory| {
                    inventory.global.node_quota.partition == item.partition
                }).count() != 1
                {
                    return Err(InitializationCauseV1::CoverageResidual);
                }
            }

            let data = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            let snapshot = physical.compare_empty_git_coverage_catalog_v1(&catalog, evidence)?;
            if snapshot.owner_uid() != owner.owner_uid {
                return Err(InitializationCauseV1::CoverageResidual);
            }
            snapshot.revalidate()?;
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }

        // Keep the owning census result before independent original-name and
        // credential checks. No later success clears an earlier failure.
        if let Err(cause) = physical.held_snapshot() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Some(source) = self.source.as_mut() {
            if let Err(cause) = source.recheck_existing() {
                self.postcheck.get_or_insert(cause.into());
            }
        }
        if let Some((hold, _)) = self.hold.as_mut() {
            if let Err(cause) = require_original_hold(
                hold, self.original_hold, self.coverage_inputs, self.original_coverage,
            ) {
                self.postcheck.get_or_insert(cause);
            }
        }
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.postcheck.get_or_insert(cause);
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck_git_coverage(owner, original_inputs)
    }

    /// Persists the original permanent denial fence for the audited Cache cohort.
    ///
    /// The nonce is only the original enrollment-flight correlation DATA.
    /// Actual fixed signed inputs and every same-owner census/bookend remain
    /// required. This creates no allocation, account, remote receipt or Drain.
    /// Cancellation, an error or a later expired input never permits retry.
    ///
    /// # Errors
    /// Retains the actual transaction, commit Result and native readback on
    /// failed reuse, nonempty owners, bounds/CAS failure or ambiguous custody.
    #[cfg(target_os = "linux")]
    pub fn enroll_empty_git_coverage_once_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &crate::physical::DormantCacheOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_prepare_nonce: [u8; 16],
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.coverage_append_started {
            return Err(CacheResidentUnavailableV1);
        }
        self.coverage_append_started = true;
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)?;
        self.complete = false;

        let clock = match self.clock.as_ref() {
            Some(clock) => clock,
            None => {
                self.first_failure.get_or_insert(InitializationCauseV1::Closed);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let held_clock = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };

        let returned = (|| {
            if original_prepare_nonce == [0; 16]
                || self.original_coverage != Some(None)
                || self.coverage_transaction.is_some()
            {
                return Err(InitializationCauseV1::CoverageAppend);
            }
            let inputs = self.coverage_inputs.ok_or(InitializationCauseV1::CoverageInputs)?;
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                .recheck_existing()?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            )?;
            let observed_seconds = held_clock.current_unix_seconds()?;
            if observed_seconds < inputs.issued_seconds || observed_seconds >= inputs.expires_seconds {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            let native = hold.0.cache_coverage_native_prefix_v1()
                .map_err(|cause| JournalError::NativePrefix(Box::new(cause)))?;
            let predecessor_prefix = native.prefix_digest();
            let provision_origin = native.provision_origin_digest();
            let data = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            let birth = enrollment.fixed_owner_birth_recipe_v1(
                &catalog, GitCoverageJournalProfileV1::CachePolicyHold, original_prepare_nonce,
            )?;
            if birth.predecessor_prefix != predecessor_prefix
                || birth.provision_origin != provision_origin
                || hold.0.snapshot_sequence().checked_add(3) != Some(birth.commit_sequence)
            {
                return Err(InitializationCauseV1::CoverageAppend);
            }
            drop(native);
            let transaction = birth.transaction;
            let birth_bytes = birth.encode()?;
            let fence = GitCoverageFenceFieldsV1 {
                owner: birth.owner,
                project: inputs.project,
                node: inputs.node,
                epoch: inputs.epoch,
                generation: inputs.generation,
                enrollment: inputs.enrollment,
                birth: GitCoverageBirthV1::decode(&birth_bytes)?.digest(),
                catalog: inputs.catalog,
                transaction,
                predecessor_prefix,
                prepare_nonce: original_prepare_nonce,
            };
            self.coverage_transaction = Some(
                hold.0.prepare_cache_git_coverage_append_v1(birth, fence)?,
            );
            let transaction = self.coverage_transaction.as_ref()
                .ok_or(InitializationCauseV1::CoverageAppend)?;
            hold.0.preflight_transactions(std::slice::from_ref(transaction))?;

            // Encoding and native preflight do not renew the original signed
            // interval. Check the same owners immediately before the append.
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                .recheck_existing()?;
            require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            )?;
            if CacheGitCoverageInputsV1::capture(original_inputs)? != inputs {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            let observed_seconds = held_clock.current_unix_seconds()?;
            if observed_seconds < inputs.issued_seconds || observed_seconds >= inputs.expires_seconds {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            self.coverage_commit = Some(hold.0.commit(transaction));
            let commit = match self.coverage_commit.as_ref() {
                Some(Ok(commit)) => *commit,
                _ => return Err(InitializationCauseV1::CoverageAppend),
            };
            self.coverage_readback = Some(
                hold.0.cache_git_coverage_observation_for_writer_v1()
                    .and_then(|observed| observed.ok_or(JournalError::boundary())),
            );
            let observed = match self.coverage_readback.as_ref() {
                Some(Ok(observed)) => *observed,
                _ => return Err(InitializationCauseV1::CoverageAppend),
            };
            let (actual_birth, actual_fence, _, sequence) = observed.original_coordinates();
            if actual_birth != birth || actual_fence != fence || sequence != commit.commit_sequence {
                return Err(InitializationCauseV1::CoverageAppend);
            }
            // Advance only to the exact successful durable successor. The
            // final bookends can still fail permanently, retaining this DATA
            // and every owning result rather than rebasing or erasing debt.
            self.original_coverage = Some(Some(observed));
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }

        if let Err(cause) = held_clock.current_unix_seconds().and_then(|observed_seconds| {
            let inputs = self.coverage_inputs
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            if observed_seconds < inputs.issued_seconds || observed_seconds >= inputs.expires_seconds {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            Ok(())
        }) {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = held_clock.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = physical.held_snapshot() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Some(source) = self.source.as_mut() {
            if let Err(cause) = source.recheck_existing() {
                self.postcheck.get_or_insert(cause.into());
            }
        }
        if let Some((hold, _)) = self.hold.as_mut() {
            if let Err(cause) = require_original_hold(
                hold, self.original_hold, self.coverage_inputs, self.original_coverage,
            ) {
                self.postcheck.get_or_insert(cause);
            }
        }
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.postcheck.get_or_insert(cause);
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        drop(held_clock);
        self.complete = true;
        self.recheck_git_coverage(owner, original_inputs)
    }

    /// Observes the current enrolled Cache coordinates under every original owner.
    ///
    /// This repeats the actual empty-cohort census and fixed-input bookends.
    /// The returned coordinates are DATA, not a held cross-owner loan or
    /// permission to allocate. A consumer must independently bookend its
    /// intervening work through these same retained owners.
    ///
    /// # Errors
    /// Permanently refuses incomplete enrollment, unknown residual state,
    /// changed originals, prior append ambiguity or expired signed inputs.
    #[cfg(target_os = "linux")]
    pub fn current_git_coverage_coordinates_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &crate::physical::DormantCacheOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(
        GitCoverageBirthFieldsV1,
        GitCoverageFenceFieldsV1,
        [u8; 32],
        u64,
    ), CacheResidentUnavailableV1> {
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)?;
        match self.original_coverage {
            Some(Some(observation)) => Ok(observation.original_coordinates()),
            _ => {
                self.complete = false;
                self.first_failure.get_or_insert(InitializationCauseV1::CoverageAppend);
                Err(CacheResidentUnavailableV1)
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn compare_fixed_git_coverage_catalog(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        original_inputs: &GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if !self.complete || self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = false;

        let clock = match self.clock.as_ref() {
            Some(clock) => clock,
            None => {
                self.first_failure.get_or_insert(InitializationCauseV1::Closed);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };

        let returned = (|| {
            let data = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            let source = self.source.as_mut().ok_or(InitializationCauseV1::Closed)?;
            source.compare_git_coverage_catalog_v1(&catalog)?;
            let evidence = self.targets.evidence.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(InitializationCauseV1::Evidence)?;
            let partitions = source.partitions().count();
            if partitions == 0 || evidence.len() != partitions {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            for profile in [
                GitCoverageJournalProfileV1::CacheAuthority,
                GitCoverageJournalProfileV1::CacheState,
                GitCoverageJournalProfileV1::CachePhysical,
            ] {
                if catalog.members().filter(|member| member.profile() == profile).count() != partitions {
                    return Err(InitializationCauseV1::CoverageInputs);
                }
                for partition in source.partitions() {
                    catalog.fixed_member(profile, *partition.as_bytes())?;
                    if !evidence.iter().any(|item| item.partition.digest() == partition) {
                        return Err(InitializationCauseV1::CoverageInputs);
                    }
                }
            }

            let state_journal = owner.state_journal.as_ref().ok_or(InitializationCauseV1::Closed)?;
            require_cache_named_writer(
                state_journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
                owner.owner_uid, cache_state_journal_limits(),
            )?;
            let mut state_prefix = state_journal.cache_state_coverage_native_prefix_v1(&catalog)
                .map_err(|cause| JournalError::NativePrefix(Box::new(cause)))?;
            state_prefix.recheck()?;

            owner.authority.check_named_location(|journal| {
                require_cache_named_writer(
                    journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_AUTHORITY_JOURNAL,
                    owner.owner_uid, cache_authority_journal_limits(),
                )?;
                for (namespace, key, _value) in journal.all_records() {
                    if namespace != RecordNamespace::DesiredState
                        || !evidence.iter().any(|item| {
                            key == item.record_key.as_slice()
                                || key.strip_prefix(CACHE_MANIFEST_KEY_PREFIX)
                                    == Some(item.partition.digest().as_bytes().as_slice())
                        })
                    {
                        return Err(JournalError::boundary());
                    }
                }
                for row in catalog.infrastructure() {
                    let attributed = evidence.iter().any(|item| {
                        catalog.fixed_member(
                            GitCoverageJournalProfileV1::CacheAuthority,
                            *item.partition.digest().as_bytes(),
                        ).is_ok_and(|member| {
                            row.attribution() == member.digest()
                                && (row.key() == item.record_key.as_slice()
                                    || row.key().strip_prefix(CACHE_MANIFEST_KEY_PREFIX)
                                        == Some(item.partition.digest().as_bytes().as_slice()))
                        })
                    });
                    if catalog.members().any(|member| {
                        member.profile() == GitCoverageJournalProfileV1::CacheAuthority
                            && member.digest() == row.attribution()
                    }) && !attributed
                    {
                        return Err(JournalError::boundary());
                    }
                }
                let mut prefix = journal.cache_authority_coverage_native_prefix_v1(&catalog)
                    .map_err(|cause| JournalError::NativePrefix(Box::new(cause)))?;
                prefix.recheck()
            })?;

            let hold = self.hold.as_ref().ok_or(InitializationCauseV1::Closed)?;
            let mut hold_prefix = hold.0.cache_hold_coverage_native_prefix_v1(&catalog)
                .map_err(|cause| JournalError::NativePrefix(Box::new(cause)))?;
            hold_prefix.recheck()?;

            guard.compare_fixed_git_coverage_catalog_v1(&catalog)?;
            Ok::<(), InitializationCauseV1>(())
        })();

        // Returned native errors are owned before the independent clock
        // bookend. Rejected comparison or unwind cannot reopen this attempt.
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn require_same_coverage_inputs(
        coverage_inputs: Option<CacheGitCoverageInputsV1>,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), InitializationCauseV1> {
        if coverage_inputs != Some(CacheGitCoverageInputsV1::capture(original_inputs)?) {
            return Err(InitializationCauseV1::CoverageInputs);
        }
        Ok(())
    }
}
