//! Dormant Git protected-journal ownership and cold replay.

use aos_sandbox_core::{ObjectDigest, ResourceId};
use sha2::{Digest as _, Sha256};

use crate::journal::Journal;
use crate::lifecycle::protected_journal_adapter::{
    ProtectedDomainJournalErrorV1, decode_reducer_payload_with_validator,
    protected_current_record_candidates_v1,
};

use super::physical_effect::{
    GitSanitizedForkConfigurationV1, GitSanitizedForkDurableAuthorityV1,
    GitSanitizedForkEffectHandoffV1, GitSanitizedForkJournalRecordV1,
};
use super::protected_evidence::GitProtectedClaimEvidenceV1;
use super::protected_journal::{
    GitJournalCommitOutcomeV1, GitJournalOutcomeUnknownV1, GitJournalRecoveryV1,
    GitJournalRetainedCommitV1, GitJournalRetainedRecoveryV1, GitProtectedJournalProjectionV1,
    GitProtectedJournalSchemaV1, GitProtectedJournalV1, GitProtectedRecordKindV1,
    GitReducerRecordV1, ReplayedGitPostcommitV1, claim_git_protected_journal_v1,
    git_protected_key_v1, git_typed_reducer_envelope_v1,
};
use super::smart_transport::{
    GitSmartJournalRecordV1, GitSmartObservationV1, decode_git_smart_journal_record_v1,
};
use super::{
    GitCheapForkV1, GitDurablePayloadV1, GitExchangePlanV1, GitJournalVerifierV1,
    GitProtectedEvidenceOwnerV1, GitSanitizedForkPrepareOutcomeV1,
    GitSanitizedForkPrepareRecoveryV1, GitSanitizedForkPrepareRetryV1,
    GitSanitizedForkProtectedReadbackOwnerV1, GitSanitizedForkRecoveryTokenV1,
    GitSanitizedForkRecoveryV1, GitSanitizedForkSettlementOutcomeV1, GitSmartDispatchStateV1,
    GitSmartEffectHandoffV1, GitSmartPrepareOutcomeV1, GitSmartPrepareRecoveryV1,
    GitSmartProtectedObservationOwnerV1, GitSmartProtectedSessionOwnerV1, GitSmartRequestV1,
    GitSmartSettlementOutcomeV1, GitSmartSettlementRecoveryV1, GitSmartSettlementRetryV1,
    GitSmartSettlementUnknownV1, GitSmartTransportErrorV1, ImmutablePackGenerationV1,
    decode_git_durable_record_v1,
};

/// Owns a cold-replayed, dormant Git adapter and its custody verifier.
pub struct GitProtectedJournalOwnerV1<'journal, 'evidence> {
    journal: GitProtectedJournalV1<'journal>,
    verifier: GitJournalVerifierV1,
    evidence_owner: &'evidence mut GitProtectedEvidenceOwnerV1,
}

impl<'journal, 'evidence> GitProtectedJournalOwnerV1<'journal, 'evidence> {
    /// Cold-replays actual current records and claims the Git adapter.
    ///
    /// Validator and boot-clock evidence must be a singular token issued by the
    /// fixed protected evidence owner. Record and checkpoint custody are
    /// derived exclusively from the protected domain journal.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed protected records, invalid validator or
    /// boot evidence, failed typed replay, or absent protected provenance.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        evidence: GitProtectedClaimEvidenceV1,
        evidence_owner: &'evidence mut GitProtectedEvidenceOwnerV1,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        let verifier = recover_git_journal_verifier_v1(journal, evidence)?;
        let claimed = claim_git_protected_journal_v1(journal, verifier.validator().clone())?;
        claimed.replay()?;
        evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;

        Ok(Self {
            journal: claimed,
            verifier,
            evidence_owner,
        })
    }

    /// Replays the current Git projection under fresh protected evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained fixed evidence is no longer current.
    #[must_use]
    pub fn replay(
        &mut self,
    ) -> Result<GitProtectedJournalProjectionV1, ProtectedDomainJournalErrorV1> {
        self.revalidate_evidence()?;
        let projection = self.journal.replay()?;
        self.revalidate_evidence()?;
        Ok(projection)
    }

    /// Durably commits one exact sanitized pack/fork/configuration intention.
    ///
    /// The returned handoff exists only after exact protected readback and
    /// retains this owner borrow across physical dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] unless the current projection has
    /// exactly the supplied pack and attached fork and evidence remains current.
    pub fn prepare_sanitized_fork<'current>(
        &'current mut self,
        operation: ResourceId,
        pack: ImmutablePackGenerationV1,
        fork: GitCheapForkV1,
        configuration: GitSanitizedForkConfigurationV1,
    ) -> Result<GitSanitizedForkPrepareOutcomeV1<'current>, GitSmartTransportErrorV1> {
        self.revalidate_smart_evidence()?;
        let projection = self
            .journal
            .replay()
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let mut packs = 0_usize;
        let mut forks = 0_usize;
        for member in projection.records() {
            if member.key().kind() != GitProtectedRecordKindV1::State {
                continue;
            }
            let payload = decode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
                member.key(),
                member.payload(),
                self.verifier.validator(),
            )
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            let durable = decode_git_durable_record_v1(payload.body(), self.verifier.validator())
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            match durable.payload() {
                GitDurablePayloadV1::Pack(candidate) if candidate == &pack => packs += 1,
                GitDurablePayloadV1::CheapFork(candidate) if candidate == &fork => forks += 1,
                _ => {}
            }
        }
        if packs != 1 || forks != 1 {
            return Err(GitSmartTransportErrorV1::CurrentStateMismatch);
        }

        let record =
            GitSanitizedForkJournalRecordV1::prepared(operation, &pack, &fork, configuration)?;
        let key = git_protected_key_v1(
            GitProtectedRecordKindV1::SanitizedForkEffect,
            record.project(),
            record.repository(),
            operation,
        )
        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let envelope = git_typed_reducer_envelope_v1(
            key,
            1,
            None,
            GitReducerRecordV1::SanitizedFork(record),
            self.verifier.validator(),
        )
        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let prepared = self
            .journal
            .plan(*operation.as_bytes(), vec![envelope])
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        match self.journal.commit_retaining(prepared) {
            GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::Applied(
                mut applied,
            )) => {
                macro_rules! reopen {
                    ($expression:expr) => {
                        match $expression {
                            Ok(value) => value,
                            Err(error) => {
                                return Ok(GitSanitizedForkPrepareOutcomeV1::ReopenRequired {
                                    custody: super::GitSanitizedForkPrepareReopenV1 {
                                        operation,
                                        pack,
                                        fork,
                                        configuration,
                                    },
                                    error,
                                });
                            }
                        }
                    };
                }
                reopen!(self.revalidate_smart_evidence());
                let capability = reopen!(
                    applied
                        .take_postcommit()
                        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let postcommit = reopen!(
                    capability
                        .consume(&self.journal)
                        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let predecessor_digest = reopen!(validate_sanitized_fork_authority(
                    &postcommit,
                    record,
                    self.verifier.validator(),
                ));
                let authority = GitSanitizedForkDurableAuthorityV1::new(
                    postcommit,
                    record,
                    predecessor_digest,
                    *operation.as_bytes(),
                );
                Ok(GitSanitizedForkPrepareOutcomeV1::Prepared(
                    GitSanitizedForkEffectHandoffV1::from_validated(
                        operation,
                        pack,
                        fork,
                        configuration,
                        authority,
                    ),
                ))
            }
            GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::OutcomeUnknown {
                pending,
                ..
            }) => Ok(GitSanitizedForkPrepareOutcomeV1::OutcomeUnknown(
                super::physical_effect::GitSanitizedForkPrepareUnknownV1 {
                    pending,
                    operation,
                    pack,
                    fork,
                    configuration,
                },
            )),
            GitJournalRetainedCommitV1::Retryable { prepared, .. } => {
                Ok(GitSanitizedForkPrepareOutcomeV1::RetryableError {
                    retry: GitSanitizedForkPrepareRetryV1 {
                        prepared,
                        operation,
                        pack,
                        fork,
                        configuration,
                    },
                    error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                })
            }
        }
    }

    /// Cold-recovers an ambiguous sanitized-fork intention commit exactly.
    ///
    /// Transient failures retain the exact pending token and inputs in the
    /// returned retryable or reopen-required classification.
    pub fn recover_sanitized_fork_prepare<'current>(
        &'current mut self,
        custody: super::physical_effect::GitSanitizedForkPrepareUnknownV1,
    ) -> GitSanitizedForkPrepareRecoveryV1<'current> {
        if let Err(error) = self.validate_current_sanitized_inputs(&custody.pack, &custody.fork) {
            return GitSanitizedForkPrepareRecoveryV1::RetryableError { custody, error };
        }
        let expected = match GitSanitizedForkJournalRecordV1::prepared(
            custody.operation,
            &custody.pack,
            &custody.fork,
            custody.configuration,
        ) {
            Ok(expected) => expected,
            Err(error) => {
                return GitSanitizedForkPrepareRecoveryV1::RetryableError { custody, error };
            }
        };
        let super::physical_effect::GitSanitizedForkPrepareUnknownV1 {
            pending,
            operation,
            pack,
            fork,
            configuration,
        } = custody;
        macro_rules! reopen {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        return GitSanitizedForkPrepareRecoveryV1::ReopenRequired {
                            custody: super::GitSanitizedForkPrepareReopenV1 {
                                operation,
                                pack,
                                fork,
                                configuration,
                            },
                            error,
                        };
                    }
                }
            };
        }
        match self.journal.recover_retaining(pending) {
            GitJournalRetainedRecoveryV1::Outcome(GitJournalRecoveryV1::Applied(mut applied)) => {
                reopen!(self.revalidate_smart_evidence());
                let capability = reopen!(
                    applied
                        .take_postcommit()
                        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let postcommit = reopen!(
                    capability
                        .consume(&self.journal)
                        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let predecessor_digest = reopen!(validate_sanitized_fork_authority(
                    &postcommit,
                    expected,
                    self.verifier.validator(),
                ));
                let authority = GitSanitizedForkDurableAuthorityV1::new(
                    postcommit,
                    expected,
                    predecessor_digest,
                    *operation.as_bytes(),
                );
                GitSanitizedForkPrepareRecoveryV1::Prepared(
                    GitSanitizedForkEffectHandoffV1::from_validated(
                        operation,
                        pack,
                        fork,
                        configuration,
                        authority,
                    ),
                )
            }
            GitJournalRetainedRecoveryV1::Outcome(GitJournalRecoveryV1::Retry(prepared)) => {
                GitSanitizedForkPrepareRecoveryV1::Retry(GitSanitizedForkPrepareRetryV1 {
                    prepared,
                    operation,
                    pack,
                    fork,
                    configuration,
                })
            }
            GitJournalRetainedRecoveryV1::Outcome(GitJournalRecoveryV1::Diverged(unknown)) => {
                GitSanitizedForkPrepareRecoveryV1::Diverged(
                    super::physical_effect::GitSanitizedForkPrepareUnknownV1 {
                        pending: unknown,
                        operation,
                        pack,
                        fork,
                        configuration,
                    },
                )
            }
            GitJournalRetainedRecoveryV1::Retryable { pending, .. } => {
                GitSanitizedForkPrepareRecoveryV1::RetryableError {
                    custody: super::physical_effect::GitSanitizedForkPrepareUnknownV1 {
                        pending,
                        operation,
                        pack,
                        fork,
                        configuration,
                    },
                    error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                }
            }
        }
    }

    /// Commits only the retained exact retry issued by protected cold recovery.
    ///
    /// Every failure classification retains either the exact transaction or
    /// all inputs needed to reconstruct an already-applied handoff.
    pub fn retry_sanitized_fork_prepare<'current>(
        &'current mut self,
        retry: GitSanitizedForkPrepareRetryV1,
    ) -> GitSanitizedForkPrepareOutcomeV1<'current> {
        if let Err(error) = self.validate_current_sanitized_inputs(&retry.pack, &retry.fork) {
            return GitSanitizedForkPrepareOutcomeV1::RetryableError { retry, error };
        }
        let expected = match GitSanitizedForkJournalRecordV1::prepared(
            retry.operation,
            &retry.pack,
            &retry.fork,
            retry.configuration,
        ) {
            Ok(expected) => expected,
            Err(error) => {
                return GitSanitizedForkPrepareOutcomeV1::RetryableError { retry, error };
            }
        };
        let GitSanitizedForkPrepareRetryV1 {
            prepared,
            operation,
            pack,
            fork,
            configuration,
        } = retry;
        macro_rules! reopen_prepare {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        return GitSanitizedForkPrepareOutcomeV1::ReopenRequired {
                            custody: super::GitSanitizedForkPrepareReopenV1 {
                                operation,
                                pack,
                                fork,
                                configuration,
                            },
                            error,
                        };
                    }
                }
            };
        }
        match self.journal.commit_retaining(prepared) {
            GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::Applied(
                mut applied,
            )) => {
                reopen_prepare!(self.revalidate_smart_evidence());
                let capability = reopen_prepare!(
                    applied
                        .take_postcommit()
                        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let postcommit = reopen_prepare!(
                    capability
                        .consume(&self.journal)
                        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let predecessor_digest = reopen_prepare!(validate_sanitized_fork_authority(
                    &postcommit,
                    expected,
                    self.verifier.validator(),
                ));
                let authority = GitSanitizedForkDurableAuthorityV1::new(
                    postcommit,
                    expected,
                    predecessor_digest,
                    *operation.as_bytes(),
                );
                GitSanitizedForkPrepareOutcomeV1::Prepared(
                    GitSanitizedForkEffectHandoffV1::from_validated(
                        operation,
                        pack,
                        fork,
                        configuration,
                        authority,
                    ),
                )
            }
            GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::OutcomeUnknown {
                pending,
                ..
            }) => GitSanitizedForkPrepareOutcomeV1::OutcomeUnknown(
                super::physical_effect::GitSanitizedForkPrepareUnknownV1 {
                    pending,
                    operation,
                    pack,
                    fork,
                    configuration,
                },
            ),
            GitJournalRetainedCommitV1::Retryable { prepared, .. } => {
                GitSanitizedForkPrepareOutcomeV1::RetryableError {
                    retry: GitSanitizedForkPrepareRetryV1 {
                        prepared,
                        operation,
                        pack,
                        fork,
                        configuration,
                    },
                    error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                }
            }
        }
    }

    /// Cold-reconstructs a handoff after durable preparation was already observed.
    pub fn reopen_sanitized_fork_prepare<'current>(
        &'current mut self,
        custody: super::GitSanitizedForkPrepareReopenV1,
    ) -> GitSanitizedForkPrepareOutcomeV1<'current> {
        let super::GitSanitizedForkPrepareReopenV1 {
            operation,
            pack,
            fork,
            configuration,
        } = custody;
        macro_rules! retain_inputs {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        return GitSanitizedForkPrepareOutcomeV1::ReopenRequired {
                            custody: super::GitSanitizedForkPrepareReopenV1 {
                                operation,
                                pack,
                                fork,
                                configuration,
                            },
                            error,
                        };
                    }
                }
            };
        }
        retain_inputs!(self.validate_current_sanitized_inputs(&pack, &fork));
        let expected = retain_inputs!(GitSanitizedForkJournalRecordV1::prepared(
            operation,
            &pack,
            &fork,
            configuration,
        ));
        retain_inputs!(self.revalidate_smart_evidence());
        let replayed = retain_inputs!(
            self.journal
                .recover_current_postcommit(*operation.as_bytes())
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let capability = match replayed {
            Some(ReplayedGitPostcommitV1::Prepared(capability)) => capability,
            Some(ReplayedGitPostcommitV1::Terminal(_)) | None => {
                return GitSanitizedForkPrepareOutcomeV1::ReopenRequired {
                    custody: super::GitSanitizedForkPrepareReopenV1 {
                        operation,
                        pack,
                        fork,
                        configuration,
                    },
                    error: GitSmartTransportErrorV1::CurrentStateMismatch,
                };
            }
        };
        let postcommit = retain_inputs!(
            capability
                .consume(&self.journal)
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let predecessor_digest = retain_inputs!(validate_sanitized_fork_authority(
            &postcommit,
            expected,
            self.verifier.validator(),
        ));
        let authority = GitSanitizedForkDurableAuthorityV1::new(
            postcommit,
            expected,
            predecessor_digest,
            *operation.as_bytes(),
        );
        GitSanitizedForkPrepareOutcomeV1::Prepared(GitSanitizedForkEffectHandoffV1::from_validated(
            operation,
            pack,
            fork,
            configuration,
            authority,
        ))
    }

    /// Replaces one prepared intention with terminal protected physical readback.
    ///
    /// Failures retain physical custody and, once planned, the exact terminal
    /// transaction needed for protected recovery.
    pub fn settle_sanitized_fork_effect<'current>(
        &'current mut self,
        recovery: GitSanitizedForkRecoveryTokenV1,
        readback_owner: &mut GitSanitizedForkProtectedReadbackOwnerV1,
    ) -> GitSanitizedForkSettlementOutcomeV1<'current> {
        macro_rules! retain {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        return GitSanitizedForkSettlementOutcomeV1::RetryableError {
                            retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                                recovery,
                                pending: super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Revalidate,
                            },
                            error,
                        };
                    }
                }
            };
        }
        retain!(self.revalidate_smart_evidence());
        let operation = recovery.operation();
        let prepared_record = retain!(GitSanitizedForkJournalRecordV1::prepared(
            operation,
            recovery.pack(),
            recovery.fork(),
            recovery.configuration(),
        ));
        let predecessor = recovery.predecessor();
        if prepared_record.intention() != recovery.intention()
            || predecessor.project() != prepared_record.project()
            || predecessor.repository() != prepared_record.repository()
            || predecessor.operation() != operation
            || predecessor.intention() != prepared_record.intention()
            || !matches!(
                predecessor.phase(),
                super::physical_effect::GitSanitizedForkJournalPhaseV1::Prepared
                    | super::physical_effect::GitSanitizedForkJournalPhaseV1::Rejected
            )
        {
            return GitSanitizedForkSettlementOutcomeV1::RetryableError {
                retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                    recovery,
                    pending:
                        super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Revalidate,
                },
                error: GitSmartTransportErrorV1::CurrentStateMismatch,
            };
        }
        let predecessor_postcommit = retain!(
            self.journal
                .recover_current_postcommit(recovery.predecessor_transaction())
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let predecessor_capability = match (predecessor.phase(), predecessor_postcommit) {
            (
                super::physical_effect::GitSanitizedForkJournalPhaseV1::Prepared,
                Some(ReplayedGitPostcommitV1::Prepared(capability)),
            )
            | (
                super::physical_effect::GitSanitizedForkJournalPhaseV1::Rejected,
                Some(ReplayedGitPostcommitV1::Terminal(capability)),
            ) => capability,
            _ => {
                return GitSanitizedForkSettlementOutcomeV1::RetryableError {
                    retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                        recovery,
                        pending:
                            super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Revalidate,
                    },
                    error: GitSmartTransportErrorV1::CurrentStateMismatch,
                };
            }
        };
        let predecessor_postcommit = retain!(
            predecessor_capability
                .consume(&self.journal)
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let predecessor_digest = retain!(validate_sanitized_fork_authority(
            &predecessor_postcommit,
            predecessor,
            self.verifier.validator(),
        ));
        if predecessor_digest != recovery.predecessor_digest() {
            return GitSanitizedForkSettlementOutcomeV1::RetryableError {
                retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                    recovery,
                    pending:
                        super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Revalidate,
                },
                error: GitSmartTransportErrorV1::CurrentStateMismatch,
            };
        }
        drop(predecessor_postcommit);
        let projection = retain!(
            self.journal
                .replay()
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let current = projection
            .records()
            .iter()
            .filter(|member| member.key().kind() == GitProtectedRecordKindV1::SanitizedForkEffect)
            .filter_map(|member| {
                let payload = decode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
                    member.key(),
                    member.payload(),
                    self.verifier.validator(),
                )
                .ok()?;
                (super::physical_effect::decode_sanitized_fork_journal_record_v1(payload.body())
                    .ok()?
                    == predecessor)
                    .then_some(member)
            })
            .collect::<Vec<_>>();
        let member = retain!(
            current
                .first()
                .filter(|_| current.len() == 1)
                .ok_or(GitSmartTransportErrorV1::CurrentStateMismatch)
        );
        let current_revision = member.revision();
        let current_digest = member.digest();
        if current_digest != recovery.predecessor_digest() {
            return GitSanitizedForkSettlementOutcomeV1::RetryableError {
                retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                    recovery,
                    pending:
                        super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Revalidate,
                },
                error: GitSmartTransportErrorV1::CurrentStateMismatch,
            };
        }
        drop(current);
        drop(projection);
        let protected = retain!(
            readback_owner
                .claim(
                    prepared_record.project(),
                    prepared_record.repository(),
                    operation,
                    prepared_record.intention(),
                    recovery.backend_receipt(),
                )
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        if !protected.matches(
            prepared_record.project(),
            prepared_record.repository(),
            operation,
            prepared_record.intention(),
            recovery.backend_receipt(),
        ) {
            return GitSanitizedForkSettlementOutcomeV1::RetryableError {
                retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                    recovery,
                    pending:
                        super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Revalidate,
                },
                error: GitSmartTransportErrorV1::CurrentStateMismatch,
            };
        }
        let terminal = retain!(GitSanitizedForkJournalRecordV1::terminal(
            predecessor,
            protected.present(),
            recovery.backend_receipt(),
            protected.receipt(),
        ));
        let next_revision = retain!(
            current_revision
                .checked_add(1)
                .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let key = retain!(
            git_protected_key_v1(
                GitProtectedRecordKindV1::SanitizedForkEffect,
                terminal.project(),
                terminal.repository(),
                operation,
            )
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let envelope = retain!(
            git_typed_reducer_envelope_v1(
                key,
                next_revision,
                Some(current_digest),
                GitReducerRecordV1::SanitizedFork(terminal),
                self.verifier.validator(),
            )
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let terminal_transaction = sanitized_fork_terminal_transaction_id(
            operation,
            terminal.intention(),
            recovery.predecessor_digest(),
        );
        let planned = retain!(
            self.journal
                .plan(terminal_transaction, vec![envelope])
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        match self.journal.commit_retaining(planned) {
            GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::Applied(
                mut applied,
            )) => {
                macro_rules! terminal_unknown {
                    ($expression:expr) => {
                        match $expression {
                            Ok(value) => value,
                            Err(_) => {
                                return GitSanitizedForkSettlementOutcomeV1::OutcomeUnknown {
                                    custody: super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                                        recovery,
                                        pending: super::physical_effect::GitSanitizedForkTerminalPendingV1::Reopen,
                                        terminal,
                                    },
                                };
                            }
                        }
                    };
                }
                terminal_unknown!(self.revalidate_smart_evidence());
                let capability = terminal_unknown!(
                    applied
                        .take_postcommit()
                        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let authority = terminal_unknown!(
                    capability
                        .consume(&self.journal)
                        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let terminal_digest = terminal_unknown!(validate_sanitized_fork_authority(
                    &authority,
                    terminal,
                    self.verifier.validator()
                ));
                if protected.present() {
                    GitSanitizedForkSettlementOutcomeV1::Observed {
                        receipt: protected.receipt(),
                    }
                } else {
                    let durable = GitSanitizedForkDurableAuthorityV1::new(
                        authority,
                        terminal,
                        terminal_digest,
                        terminal_transaction,
                    );
                    GitSanitizedForkSettlementOutcomeV1::ExactRetry(
                        super::GitSanitizedForkExactRetryV1::from_validated(
                            operation,
                            recovery.pack().clone(),
                            recovery.fork().clone(),
                            recovery.configuration(),
                            durable,
                        ),
                    )
                }
            }
            GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::OutcomeUnknown {
                pending,
                ..
            }) => GitSanitizedForkSettlementOutcomeV1::OutcomeUnknown {
                custody: super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                    recovery,
                    pending:
                        super::physical_effect::GitSanitizedForkTerminalPendingV1::OutcomeUnknown(
                            pending,
                        ),
                    terminal,
                },
            },
            GitJournalRetainedCommitV1::Retryable { prepared, .. } => {
                GitSanitizedForkSettlementOutcomeV1::RetryableError {
                    retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                        recovery,
                        pending: super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Terminal {
                            prepared,
                            terminal,
                        },
                    },
                    error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                }
            }
        }
    }

    /// Recovers ambiguous terminal durability without dropping either custody token.
    pub fn recover_sanitized_fork_settlement<'current>(
        &'current mut self,
        custody: super::physical_effect::GitSanitizedForkSettlementUnknownV1,
        readback_owner: &mut GitSanitizedForkProtectedReadbackOwnerV1,
    ) -> super::GitSanitizedForkSettlementRecoveryV1<'current> {
        let super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
            recovery,
            pending,
            terminal,
        } = custody;
        let current_readback = match readback_owner.claim(
            terminal.project(),
            terminal.repository(),
            terminal.operation(),
            terminal.intention(),
            terminal.backend_receipt(),
        ) {
            Ok(readback) => readback,
            Err(_) => {
                return super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(
                    super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                        recovery,
                        pending,
                        terminal,
                    },
                );
            }
        };
        let current_terminal = match GitSanitizedForkJournalRecordV1::terminal(
            recovery.predecessor(),
            current_readback.present(),
            recovery.backend_receipt(),
            current_readback.receipt(),
        ) {
            Ok(current) if current == terminal => current,
            _ => {
                return super::GitSanitizedForkSettlementRecoveryV1::Diverged(
                    super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                        recovery,
                        pending,
                        terminal,
                    },
                );
            }
        };
        let _ = current_terminal;
        let recovered = match pending {
            super::physical_effect::GitSanitizedForkTerminalPendingV1::OutcomeUnknown(pending) => {
                match self.journal.recover_retaining(pending) {
                    GitJournalRetainedRecoveryV1::Outcome(outcome) => outcome,
                    GitJournalRetainedRecoveryV1::Retryable { pending, .. } => {
                        return super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(
                            super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                                recovery,
                                pending: super::physical_effect::GitSanitizedForkTerminalPendingV1::OutcomeUnknown(pending),
                                terminal,
                            },
                        );
                    }
                }
            }
            super::physical_effect::GitSanitizedForkTerminalPendingV1::Retry(prepared) => {
                GitJournalRecoveryV1::Retry(prepared)
            }
            super::physical_effect::GitSanitizedForkTerminalPendingV1::Reopen => {
                return match self.recover_sanitized_fork_effect(recovery, readback_owner) {
                    GitSanitizedForkRecoveryV1::Observed(receipt) => {
                        super::GitSanitizedForkSettlementRecoveryV1::Observed(receipt)
                    }
                    GitSanitizedForkRecoveryV1::ExactRetry(retry) => {
                        super::GitSanitizedForkSettlementRecoveryV1::ExactRetry(retry)
                    }
                    GitSanitizedForkRecoveryV1::Diverged(recovery) => {
                        super::GitSanitizedForkSettlementRecoveryV1::Diverged(
                            super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                                recovery,
                                pending:
                                    super::physical_effect::GitSanitizedForkTerminalPendingV1::Reopen,
                                terminal,
                            },
                        )
                    }
                    GitSanitizedForkRecoveryV1::RetryableError { recovery, .. } => {
                        super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(
                            super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                                recovery,
                                pending: super::physical_effect::GitSanitizedForkTerminalPendingV1::Reopen,
                                terminal,
                            },
                        )
                    }
                    GitSanitizedForkRecoveryV1::SettlementOutcomeUnknown(custody) => {
                        super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(custody)
                    }
                    GitSanitizedForkRecoveryV1::SettlementRetryable { retry, error } => {
                        super::GitSanitizedForkSettlementRecoveryV1::RetryableError { retry, error }
                    }
                };
            }
        };
        match recovered {
            GitJournalRecoveryV1::Diverged(pending) => {
                super::GitSanitizedForkSettlementRecoveryV1::Diverged(
                    super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                        recovery,
                        pending:
                            super::physical_effect::GitSanitizedForkTerminalPendingV1::OutcomeUnknown(
                                pending,
                            ),
                        terminal,
                    },
                )
            }
            GitJournalRecoveryV1::Applied(applied) => {
                drop(applied);
                self.classify_recovered_sanitized_fork(recovery, terminal, readback_owner)
            }
            GitJournalRecoveryV1::Retry(prepared) => {
                match self.journal.commit_retaining(prepared) {
                    GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::Applied(applied)) => {
                        drop(applied);
                        self.classify_recovered_sanitized_fork(
                            recovery,
                            terminal,
                            readback_owner,
                        )
                    }
                    GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::OutcomeUnknown { pending, .. }) => {
                        super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(
                            super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                                recovery,
                                pending: super::physical_effect::GitSanitizedForkTerminalPendingV1::OutcomeUnknown(pending),
                                terminal,
                            },
                        )
                    }
                    GitJournalRetainedCommitV1::Retryable { prepared, .. } => {
                        super::GitSanitizedForkSettlementRecoveryV1::RetryableError {
                            retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                                recovery,
                                pending: super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Terminal {
                                    prepared,
                                    terminal,
                                },
                            },
                            error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                        }
                    }
                }
            }
        }
    }

    /// Retries only the exact retained terminal replacement transaction.
    pub fn retry_sanitized_fork_settlement<'current>(
        &'current mut self,
        retry: super::physical_effect::GitSanitizedForkSettlementRetryV1,
        readback_owner: &mut GitSanitizedForkProtectedReadbackOwnerV1,
    ) -> super::GitSanitizedForkSettlementRecoveryV1<'current> {
        let super::physical_effect::GitSanitizedForkSettlementRetryV1 { recovery, pending } = retry;
        let (prepared, terminal) = match pending {
            super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Revalidate => {
                return match self.settle_sanitized_fork_effect(recovery, readback_owner) {
                    GitSanitizedForkSettlementOutcomeV1::Observed { receipt } => {
                        super::GitSanitizedForkSettlementRecoveryV1::Observed(receipt)
                    }
                    GitSanitizedForkSettlementOutcomeV1::ExactRetry(retry) => {
                        super::GitSanitizedForkSettlementRecoveryV1::ExactRetry(retry)
                    }
                    GitSanitizedForkSettlementOutcomeV1::OutcomeUnknown { custody } => {
                        super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(custody)
                    }
                    GitSanitizedForkSettlementOutcomeV1::RetryableError { retry, error } => {
                        super::GitSanitizedForkSettlementRecoveryV1::RetryableError { retry, error }
                    }
                };
            }
            super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Terminal {
                prepared,
                terminal,
            } => (prepared, terminal),
        };
        let current_readback = match readback_owner.claim(
            terminal.project(),
            terminal.repository(),
            terminal.operation(),
            terminal.intention(),
            terminal.backend_receipt(),
        ) {
            Ok(readback) => readback,
            Err(_) => {
                return super::GitSanitizedForkSettlementRecoveryV1::RetryableError {
                    retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                        recovery,
                        pending:
                            super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Terminal {
                                prepared,
                                terminal,
                            },
                    },
                    error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                };
            }
        };
        let current_terminal = GitSanitizedForkJournalRecordV1::terminal(
            recovery.predecessor(),
            current_readback.present(),
            recovery.backend_receipt(),
            current_readback.receipt(),
        );
        if !matches!(current_terminal, Ok(current) if current == terminal) {
            return super::GitSanitizedForkSettlementRecoveryV1::RetryableError {
                retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                    recovery,
                    pending:
                        super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Terminal {
                            prepared,
                            terminal,
                        },
                },
                error: GitSmartTransportErrorV1::CurrentStateMismatch,
            };
        }
        match self.journal.commit_retaining(prepared) {
            GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::Applied(applied)) => {
                drop(applied);
                self.classify_recovered_sanitized_fork(recovery, terminal, readback_owner)
            }
            GitJournalRetainedCommitV1::Outcome(GitJournalCommitOutcomeV1::OutcomeUnknown {
                pending,
                ..
            }) => super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(
                super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                    recovery,
                    pending:
                        super::physical_effect::GitSanitizedForkTerminalPendingV1::OutcomeUnknown(
                            pending,
                        ),
                    terminal,
                },
            ),
            GitJournalRetainedCommitV1::Retryable { prepared, .. } => {
                super::GitSanitizedForkSettlementRecoveryV1::RetryableError {
                    retry: super::physical_effect::GitSanitizedForkSettlementRetryV1 {
                        recovery,
                        pending: super::physical_effect::GitSanitizedForkSettlementRetryKindV1::Terminal {
                            prepared,
                            terminal,
                        },
                    },
                    error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                }
            }
        }
    }

    fn classify_recovered_sanitized_fork<'current>(
        &'current mut self,
        recovery: GitSanitizedForkRecoveryTokenV1,
        terminal: GitSanitizedForkJournalRecordV1,
        readback_owner: &mut GitSanitizedForkProtectedReadbackOwnerV1,
    ) -> super::GitSanitizedForkSettlementRecoveryV1<'current> {
        match self.recover_sanitized_fork_effect(recovery, readback_owner) {
            GitSanitizedForkRecoveryV1::Observed(receipt) => {
                super::GitSanitizedForkSettlementRecoveryV1::Observed(receipt)
            }
            GitSanitizedForkRecoveryV1::ExactRetry(retry) => {
                super::GitSanitizedForkSettlementRecoveryV1::ExactRetry(retry)
            }
            GitSanitizedForkRecoveryV1::Diverged(recovery) => {
                super::GitSanitizedForkSettlementRecoveryV1::Diverged(
                    super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                        recovery,
                        pending: super::physical_effect::GitSanitizedForkTerminalPendingV1::Reopen,
                        terminal,
                    },
                )
            }
            GitSanitizedForkRecoveryV1::RetryableError { recovery, .. } => {
                super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(
                    super::physical_effect::GitSanitizedForkSettlementUnknownV1 {
                        recovery,
                        pending: super::physical_effect::GitSanitizedForkTerminalPendingV1::Reopen,
                        terminal,
                    },
                )
            }
            GitSanitizedForkRecoveryV1::SettlementOutcomeUnknown(custody) => {
                super::GitSanitizedForkSettlementRecoveryV1::OutcomeUnknown(custody)
            }
            GitSanitizedForkRecoveryV1::SettlementRetryable { retry, error } => {
                super::GitSanitizedForkSettlementRecoveryV1::RetryableError { retry, error }
            }
        }
    }

    fn terminalize_recovered_sanitized_fork<'current>(
        &'current mut self,
        recovery: GitSanitizedForkRecoveryTokenV1,
        readback_owner: &mut GitSanitizedForkProtectedReadbackOwnerV1,
    ) -> GitSanitizedForkRecoveryV1<'current> {
        match self.settle_sanitized_fork_effect(recovery, readback_owner) {
            GitSanitizedForkSettlementOutcomeV1::Observed { receipt } => {
                GitSanitizedForkRecoveryV1::Observed(receipt)
            }
            GitSanitizedForkSettlementOutcomeV1::ExactRetry(retry) => {
                GitSanitizedForkRecoveryV1::ExactRetry(retry)
            }
            GitSanitizedForkSettlementOutcomeV1::OutcomeUnknown { custody } => {
                GitSanitizedForkRecoveryV1::SettlementOutcomeUnknown(custody)
            }
            GitSanitizedForkSettlementOutcomeV1::RetryableError { retry, error } => {
                GitSanitizedForkRecoveryV1::SettlementRetryable { retry, error }
            }
        }
    }

    /// Cold-reopens an outcome-unknown physical effect and permits only exact retry.
    ///
    /// Transient replay failures retain the recovery token. Missing or
    /// substituted state returns `Diverged` without retry authority.
    pub fn recover_sanitized_fork_effect<'current>(
        &'current mut self,
        recovery: GitSanitizedForkRecoveryTokenV1,
        readback_owner: &mut GitSanitizedForkProtectedReadbackOwnerV1,
    ) -> GitSanitizedForkRecoveryV1<'current> {
        macro_rules! retain_recovery {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        return GitSanitizedForkRecoveryV1::RetryableError { recovery, error };
                    }
                }
            };
        }
        retain_recovery!(self.revalidate_smart_evidence());
        let operation = recovery.operation();
        let expected = retain_recovery!(GitSanitizedForkJournalRecordV1::prepared(
            operation,
            recovery.pack(),
            recovery.fork(),
            recovery.configuration(),
        ));
        if expected.intention() != recovery.intention() {
            return GitSanitizedForkRecoveryV1::Diverged(recovery);
        }
        let terminal_transaction = sanitized_fork_terminal_transaction_id(
            operation,
            expected.intention(),
            recovery.predecessor_digest(),
        );
        let terminal_replay = retain_recovery!(
            self.journal
                .recover_current_postcommit(terminal_transaction)
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let rejected_predecessor = match terminal_replay {
            Some(ReplayedGitPostcommitV1::Terminal(capability)) => {
                let postcommit = retain_recovery!(
                    capability
                        .consume(&self.journal)
                        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let record = retain_recovery!(decode_sanitized_fork_authority(
                    &postcommit,
                    self.verifier.validator()
                ));
                let envelope = match postcommit.records().first() {
                    Some(member) if postcommit.records().len() == 1 => member.envelope(),
                    _ => return GitSanitizedForkRecoveryV1::Diverged(recovery),
                };
                (record == recovery.predecessor()
                    && record.phase()
                        == super::physical_effect::GitSanitizedForkJournalPhaseV1::Rejected)
                    .then_some(envelope.digest() == recovery.predecessor_digest())
            }
            Some(ReplayedGitPostcommitV1::Prepared(_)) | None => None,
        };
        match rejected_predecessor {
            Some(true) => {
                return self.terminalize_recovered_sanitized_fork(recovery, readback_owner);
            }
            Some(false) => return GitSanitizedForkRecoveryV1::Diverged(recovery),
            None => {}
        }
        let replayed = retain_recovery!(
            self.journal
                .recover_current_postcommit(terminal_transaction)
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
        );
        let replayed = match replayed {
            Some(replayed) => replayed,
            None => match retain_recovery!(
                self.journal
                    .recover_current_postcommit(recovery.predecessor_transaction())
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
            ) {
                Some(replayed) => replayed,
                None => return GitSanitizedForkRecoveryV1::Diverged(recovery),
            },
        };
        match replayed {
            ReplayedGitPostcommitV1::Prepared(capability) => {
                let postcommit = retain_recovery!(
                    capability
                        .consume(&self.journal)
                        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let predecessor_digest = retain_recovery!(validate_sanitized_fork_authority(
                    &postcommit,
                    recovery.predecessor(),
                    self.verifier.validator(),
                ));
                if predecessor_digest != recovery.predecessor_digest() {
                    return GitSanitizedForkRecoveryV1::Diverged(recovery);
                }
                drop(postcommit);
                self.terminalize_recovered_sanitized_fork(recovery, readback_owner)
            }
            ReplayedGitPostcommitV1::Terminal(capability) => {
                let postcommit = retain_recovery!(
                    capability
                        .consume(&self.journal)
                        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let record = retain_recovery!(decode_sanitized_fork_authority(
                    &postcommit,
                    self.verifier.validator()
                ));
                let envelope = match postcommit.records().first() {
                    Some(member) if postcommit.records().len() == 1 => member.envelope(),
                    _ => return GitSanitizedForkRecoveryV1::Diverged(recovery),
                };
                if record == recovery.predecessor()
                    && record.phase()
                        == super::physical_effect::GitSanitizedForkJournalPhaseV1::Rejected
                {
                    return GitSanitizedForkRecoveryV1::Diverged(recovery);
                }
                if record.project() != expected.project()
                    || record.repository() != expected.repository()
                    || record.operation() != expected.operation()
                    || record.intention() != expected.intention()
                    || record.backend_receipt() != recovery.backend_receipt()
                    || envelope.predecessor() != Some(recovery.predecessor_digest())
                {
                    return GitSanitizedForkRecoveryV1::Diverged(recovery);
                }
                let current_readback = match readback_owner.claim(
                    expected.project(),
                    expected.repository(),
                    operation,
                    expected.intention(),
                    recovery.backend_receipt(),
                ) {
                    Ok(readback) => readback,
                    Err(_) => {
                        return GitSanitizedForkRecoveryV1::RetryableError {
                            recovery,
                            error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                        };
                    }
                };
                let receipt = retain_recovery!(
                    record
                        .receipt()
                        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
                );
                let terminal_present = record.phase()
                    == super::physical_effect::GitSanitizedForkJournalPhaseV1::Completed;
                if !current_readback.matches(
                    expected.project(),
                    expected.repository(),
                    operation,
                    expected.intention(),
                    recovery.backend_receipt(),
                ) || current_readback.present() != terminal_present
                    || current_readback.receipt() != receipt
                {
                    return GitSanitizedForkRecoveryV1::Diverged(recovery);
                }
                match record.phase() {
                    super::physical_effect::GitSanitizedForkJournalPhaseV1::Completed => {
                        GitSanitizedForkRecoveryV1::Observed(receipt)
                    }
                    super::physical_effect::GitSanitizedForkJournalPhaseV1::Rejected => {
                        let terminal_digest = retain_recovery!(validate_sanitized_fork_authority(
                            &postcommit,
                            record,
                            self.verifier.validator(),
                        ));
                        let authority = GitSanitizedForkDurableAuthorityV1::new(
                            postcommit,
                            record,
                            terminal_digest,
                            terminal_transaction,
                        );
                        GitSanitizedForkRecoveryV1::ExactRetry(
                            super::GitSanitizedForkExactRetryV1::from_validated(
                                operation,
                                recovery.pack().clone(),
                                recovery.fork().clone(),
                                recovery.configuration(),
                                authority,
                            ),
                        )
                    }
                    super::physical_effect::GitSanitizedForkJournalPhaseV1::Prepared => {
                        GitSanitizedForkRecoveryV1::RetryableError {
                            recovery,
                            error: GitSmartTransportErrorV1::ProtectedEvidenceUnavailable,
                        }
                    }
                }
            }
        }
    }

    /// Prepares one standard upload-pack or receive-pack exchange.
    ///
    /// The exact plan must reproduce a current protected export or repository
    /// snapshot. This method performs no Git, filesystem, or network effect.
    /// The returned handoff keeps this fixed owner mutably borrowed.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] for endpoint mismatch, missing or
    /// ambiguous protected state, typed replay failure, or stale evidence.
    pub fn prepare_smart_exchange<'current>(
        &'current mut self,
        request: GitSmartRequestV1,
        session_owner: &'current mut GitSmartProtectedSessionOwnerV1,
        plan: GitExchangePlanV1,
    ) -> Result<GitSmartPrepareOutcomeV1<'current>, GitSmartTransportErrorV1> {
        let session = session_owner
            .claim(request, &plan)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        if !super::smart_transport::plan_matches_endpoint(request, &plan)
            || !super::smart_transport::session_matches_plan(&session, request, &plan)
        {
            return Err(GitSmartTransportErrorV1::EndpointMismatch);
        }
        self.revalidate_smart_evidence()?;
        let projection = self
            .journal
            .replay()
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let mut matching = 0_usize;
        for record in projection.records() {
            let kind = record.key().kind();
            if matches!(
                kind,
                GitProtectedRecordKindV1::Checkpoint
                    | GitProtectedRecordKindV1::SmartEffect
                    | GitProtectedRecordKindV1::SmartTerminal
                    | GitProtectedRecordKindV1::SanitizedForkEffect
            ) {
                continue;
            }
            let payload = decode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
                record.key(),
                record.payload(),
                self.verifier.validator(),
            )
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            let durable = decode_git_durable_record_v1(payload.body(), self.verifier.validator())
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            if !matches!(
                (kind, durable.payload()),
                (
                    GitProtectedRecordKindV1::State,
                    GitDurablePayloadV1::Repository(_)
                        | GitDurablePayloadV1::Export(_)
                        | GitDurablePayloadV1::Pack(_)
                        | GitDurablePayloadV1::PackLease(_)
                        | GitDurablePayloadV1::CheapFork(_)
                ) | (
                    GitProtectedRecordKindV1::ExchangeEffect,
                    GitDurablePayloadV1::Receive(_)
                ) | (
                    GitProtectedRecordKindV1::Publication,
                    GitDurablePayloadV1::Publication(_)
                )
            ) {
                return Err(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable);
            }
            if durable_record_matches_plan(durable.payload(), &plan) {
                matching = matching
                    .checked_add(1)
                    .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            }
        }
        if matching != 1 {
            return Err(GitSmartTransportErrorV1::CurrentStateMismatch);
        }
        self.revalidate_smart_evidence()?;
        session_owner
            .claim(request, &plan)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let exchange = super::smart_transport::exchange_id(&plan);
        let record = GitSmartJournalRecordV1::prepared(request, plan);
        let endpoint = request.endpoint();
        let key = git_protected_key_v1(
            GitProtectedRecordKindV1::SmartEffect,
            endpoint.project(),
            endpoint.repository(),
            exchange,
        )
        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let envelope = git_typed_reducer_envelope_v1(
            key,
            1,
            None,
            GitReducerRecordV1::Smart(&record),
            self.verifier.validator(),
        )
        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let prepared = self
            .journal
            .plan(*exchange.as_bytes(), vec![envelope])
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        match self
            .journal
            .commit(prepared)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
        {
            GitJournalCommitOutcomeV1::Applied(mut applied) => {
                self.revalidate_smart_evidence()?;
                let session = session_owner
                    .claim(request, record.state().plan())
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
                validate_smart_effect_authority(&authority, &record, self.verifier.validator())?;
                Ok(GitSmartPrepareOutcomeV1::Prepared(
                    GitSmartEffectHandoffV1::new(
                        record.state().clone(),
                        session.authority_fence(),
                        authority,
                    ),
                ))
            }
            GitJournalCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                Ok(GitSmartPrepareOutcomeV1::OutcomeUnknown(pending))
            }
        }
    }

    /// Recovers one ambiguous pre-effect smart-transport commit exactly.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] when protected evidence is stale.
    pub fn recover_smart_prepare<'current>(
        &'current mut self,
        pending: GitJournalOutcomeUnknownV1,
        request: GitSmartRequestV1,
        plan: GitExchangePlanV1,
        session_owner: &'current mut GitSmartProtectedSessionOwnerV1,
    ) -> Result<GitSmartPrepareRecoveryV1<'current>, GitSmartTransportErrorV1> {
        session_owner
            .claim(request, &plan)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let expected = GitSmartJournalRecordV1::prepared(request, plan.clone());
        match self
            .journal
            .recover(pending)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
        {
            GitJournalRecoveryV1::Applied(mut applied) => {
                self.revalidate_smart_evidence()?;
                let session = session_owner
                    .claim(request, expected.state().plan())
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
                validate_smart_effect_authority(&authority, &expected, self.verifier.validator())?;
                Ok(GitSmartPrepareRecoveryV1::Prepared(
                    GitSmartEffectHandoffV1::new(
                        expected.state().clone(),
                        session.authority_fence(),
                        authority,
                    ),
                ))
            }
            GitJournalRecoveryV1::Retry(prepared) => Ok(GitSmartPrepareRecoveryV1::Retry(prepared)),
            GitJournalRecoveryV1::Diverged(unknown) => {
                Ok(GitSmartPrepareRecoveryV1::Diverged(unknown))
            }
        }
    }

    /// Commits the sole exact retry returned by pre-effect recovery.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] when protected session evidence no
    /// longer reproduces the exact request and protocol-v2 plan.
    pub fn retry_smart_prepare<'current>(
        &'current mut self,
        prepared: super::protected_journal::PreparedGitJournalTransactionV1,
        request: GitSmartRequestV1,
        plan: GitExchangePlanV1,
        session_owner: &'current mut GitSmartProtectedSessionOwnerV1,
    ) -> Result<GitSmartPrepareOutcomeV1<'current>, GitSmartTransportErrorV1> {
        session_owner
            .claim(request, &plan)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let expected = GitSmartJournalRecordV1::prepared(request, plan);
        match self
            .journal
            .commit(prepared)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
        {
            GitJournalCommitOutcomeV1::Applied(mut applied) => {
                self.revalidate_smart_evidence()?;
                let session = session_owner
                    .claim(request, expected.state().plan())
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
                validate_smart_effect_authority(&authority, &expected, self.verifier.validator())?;
                Ok(GitSmartPrepareOutcomeV1::Prepared(
                    GitSmartEffectHandoffV1::new(
                        expected.state().clone(),
                        session.authority_fence(),
                        authority,
                    ),
                ))
            }
            GitJournalCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                Ok(GitSmartPrepareOutcomeV1::OutcomeUnknown(pending))
            }
        }
    }

    /// Resolves one outcome-unknown smart exchange under fresh fixed replay.
    ///
    /// Any replay, evidence, or observation failure retains the original
    /// indeterminate state and therefore cannot become blind retry authority.
    #[must_use]
    pub fn settle_smart_exchange(
        &mut self,
        state: GitSmartDispatchStateV1,
        observation_owner: &mut GitSmartProtectedObservationOwnerV1,
    ) -> Result<GitSmartSettlementOutcomeV1, GitSmartTransportErrorV1> {
        if !matches!(
            state.phase(),
            super::GitSmartDispatchPhaseV1::Prepared
                | super::GitSmartDispatchPhaseV1::Indeterminate
        ) {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        let projection = self
            .replay()
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let prepared_record =
            GitSmartJournalRecordV1::prepared(state.request(), state.plan().clone());
        let mut matching = 0_usize;
        for record in projection
            .records()
            .iter()
            .filter(|record| record.key().kind() == GitProtectedRecordKindV1::SmartEffect)
        {
            let payload = decode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
                record.key(),
                record.payload(),
                self.verifier.validator(),
            )
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            if decode_git_smart_journal_record_v1(payload.body(), self.verifier.validator())
                .is_ok_and(|candidate| candidate == prepared_record)
            {
                matching = matching
                    .checked_add(1)
                    .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            }
        }
        if matching != 1 {
            return Err(GitSmartTransportErrorV1::CurrentStateMismatch);
        }
        let protected = observation_owner
            .claim(state.plan())
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let observation = GitSmartObservationV1::from_protected(
            protected.exchange(),
            protected.accepted(),
            protected.receipt(),
        )?;
        let terminal = GitSmartJournalRecordV1::terminal(
            &prepared_record,
            observation,
            protected.commitment(),
        )?;
        let endpoint = state.request().endpoint();
        let exchange = super::smart_transport::exchange_id(state.plan());
        let key = git_protected_key_v1(
            GitProtectedRecordKindV1::SmartTerminal,
            endpoint.project(),
            endpoint.repository(),
            exchange,
        )
        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let envelope = git_typed_reducer_envelope_v1(
            key,
            1,
            None,
            GitReducerRecordV1::Smart(&terminal),
            self.verifier.validator(),
        )
        .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let prepared = self
            .journal
            .plan(git_terminal_transaction_id(exchange), vec![envelope])
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        match self
            .journal
            .commit(prepared)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
        {
            GitJournalCommitOutcomeV1::Applied(_) => {
                self.revalidate_smart_evidence()?;
                Ok(GitSmartSettlementOutcomeV1::Applied(
                    terminal.state().clone(),
                ))
            }
            GitJournalCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                Ok(GitSmartSettlementOutcomeV1::OutcomeUnknown(
                    GitSmartSettlementUnknownV1::new(terminal, pending),
                ))
            }
        }
    }

    /// Recovers one ambiguous terminal smart-transport publication exactly.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] when protected replay fails.
    pub fn recover_smart_settlement(
        &mut self,
        unknown: GitSmartSettlementUnknownV1,
    ) -> Result<GitSmartSettlementRecoveryV1, GitSmartTransportErrorV1> {
        let (terminal, pending) = unknown.into_parts();
        match self
            .journal
            .recover(pending)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
        {
            GitJournalRecoveryV1::Applied(mut applied) => {
                self.revalidate_smart_evidence()?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
                validate_smart_terminal_authority(
                    &authority,
                    &terminal,
                    self.verifier.validator(),
                )?;
                Ok(GitSmartSettlementRecoveryV1::Applied(
                    terminal.state().clone(),
                ))
            }
            GitJournalRecoveryV1::Retry(prepared) => Ok(GitSmartSettlementRecoveryV1::Retry(
                GitSmartSettlementRetryV1::new(terminal, prepared),
            )),
            GitJournalRecoveryV1::Diverged(pending) => Ok(GitSmartSettlementRecoveryV1::Diverged(
                GitSmartSettlementUnknownV1::new(terminal, pending),
            )),
        }
    }

    /// Commits the sole exact retry returned by terminal recovery.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] when protected currentness or exact
    /// terminal readback fails.
    pub fn retry_smart_settlement(
        &mut self,
        retry: GitSmartSettlementRetryV1,
    ) -> Result<GitSmartSettlementOutcomeV1, GitSmartTransportErrorV1> {
        let (terminal, prepared) = retry.into_parts();
        match self
            .journal
            .commit(prepared)
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
        {
            GitJournalCommitOutcomeV1::Applied(mut applied) => {
                self.revalidate_smart_evidence()?;
                let authority = applied
                    .take_postcommit()
                    .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?
                    .consume(&self.journal)
                    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
                validate_smart_terminal_authority(
                    &authority,
                    &terminal,
                    self.verifier.validator(),
                )?;
                Ok(GitSmartSettlementOutcomeV1::Applied(
                    terminal.state().clone(),
                ))
            }
            GitJournalCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                Ok(GitSmartSettlementOutcomeV1::OutcomeUnknown(
                    GitSmartSettlementUnknownV1::new(terminal, pending),
                ))
            }
        }
    }

    fn revalidate_evidence(&mut self) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
    }

    fn revalidate_smart_evidence(&mut self) -> Result<(), GitSmartTransportErrorV1> {
        self.revalidate_evidence()
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
    }

    fn validate_current_sanitized_inputs(
        &mut self,
        pack: &ImmutablePackGenerationV1,
        fork: &GitCheapForkV1,
    ) -> Result<(), GitSmartTransportErrorV1> {
        self.revalidate_smart_evidence()?;
        let projection = self
            .journal
            .replay()
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
        let mut packs = 0_usize;
        let mut forks = 0_usize;
        for member in projection.records() {
            if member.key().kind() != GitProtectedRecordKindV1::State {
                continue;
            }
            let payload = decode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
                member.key(),
                member.payload(),
                self.verifier.validator(),
            )
            .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            let durable = decode_git_durable_record_v1(payload.body(), self.verifier.validator())
                .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
            match durable.payload() {
                GitDurablePayloadV1::Pack(candidate) if candidate == pack => packs += 1,
                GitDurablePayloadV1::CheapFork(candidate) if candidate == fork => forks += 1,
                _ => {}
            }
        }
        if packs != 1 || forks != 1 {
            return Err(GitSmartTransportErrorV1::CurrentStateMismatch);
        }
        Ok(())
    }
}

fn durable_record_matches_plan(payload: &GitDurablePayloadV1, plan: &GitExchangePlanV1) -> bool {
    match (payload, plan) {
        (GitDurablePayloadV1::Export(candidate), GitExchangePlanV1::Upload(upload)) => {
            candidate.export() == upload.export()
        }
        (GitDurablePayloadV1::Repository(candidate), GitExchangePlanV1::Receive(receive)) => {
            candidate.repository() == receive.repository()
                && candidate.refs() == receive.current_refs()
                && candidate.ref_map() == receive.pre_ref_map()
                && candidate.database() == receive.pre_database()
        }
        _ => false,
    }
}

fn validate_smart_effect_authority(
    authority: &super::protected_journal::ValidatedGitPostcommitV1<'_>,
    expected: &GitSmartJournalRecordV1,
    validator: &super::GitTrustedValidatorV1,
) -> Result<(), GitSmartTransportErrorV1> {
    let records = authority.records();
    let record = records
        .first()
        .filter(|_| records.len() == 1)
        .filter(|record| record.is_effect())
        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
    let envelope = record.envelope();
    let payload = decode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
        envelope.key(),
        envelope.payload(),
        validator,
    )
    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
    let decoded = decode_git_smart_journal_record_v1(payload.body(), validator)?;
    if decoded != *expected {
        return Err(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable);
    }
    Ok(())
}

fn validate_sanitized_fork_authority(
    authority: &super::protected_journal::ValidatedGitPostcommitV1<'_>,
    expected: GitSanitizedForkJournalRecordV1,
    validator: &super::GitTrustedValidatorV1,
) -> Result<ObjectDigest, GitSmartTransportErrorV1> {
    let decoded = decode_sanitized_fork_authority(authority, validator)?;
    if decoded != expected {
        return Err(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable);
    }
    authority
        .records()
        .first()
        .filter(|_| authority.records().len() == 1)
        .map(|record| record.envelope().digest())
        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)
}

fn decode_sanitized_fork_authority(
    authority: &super::protected_journal::ValidatedGitPostcommitV1<'_>,
    validator: &super::GitTrustedValidatorV1,
) -> Result<GitSanitizedForkJournalRecordV1, GitSmartTransportErrorV1> {
    let records = authority.records();
    let record = records
        .first()
        .filter(|_| records.len() == 1)
        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
    if record.envelope().key().kind() != GitProtectedRecordKindV1::SanitizedForkEffect {
        return Err(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable);
    }
    let payload = decode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
        record.envelope().key(),
        record.envelope().payload(),
        validator,
    )
    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
    super::physical_effect::decode_sanitized_fork_journal_record_v1(payload.body())
}

fn validate_smart_terminal_authority(
    authority: &super::protected_journal::ValidatedGitPostcommitV1<'_>,
    expected: &GitSmartJournalRecordV1,
    validator: &super::GitTrustedValidatorV1,
) -> Result<(), GitSmartTransportErrorV1> {
    let records = authority.records();
    let record = records
        .first()
        .filter(|_| records.len() == 1)
        .filter(|record| record.is_publication())
        .ok_or(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
    let envelope = record.envelope();
    let payload = decode_reducer_payload_with_validator::<GitProtectedJournalSchemaV1>(
        envelope.key(),
        envelope.payload(),
        validator,
    )
    .map_err(|_| GitSmartTransportErrorV1::ProtectedEvidenceUnavailable)?;
    let decoded = decode_git_smart_journal_record_v1(payload.body(), validator)?;
    if decoded != *expected {
        return Err(GitSmartTransportErrorV1::ProtectedEvidenceUnavailable);
    }
    Ok(())
}

fn git_terminal_transaction_id(exchange: aos_sandbox_core::ResourceId) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.git.smart-terminal-transaction.v1\0")
        .chain_update(exchange.as_bytes())
        .finalize();
    let mut transaction = [0_u8; 16];
    transaction.copy_from_slice(&digest[..16]);
    transaction
}

fn sanitized_fork_terminal_transaction_id(
    operation: ResourceId,
    intention: ObjectDigest,
    predecessor: ObjectDigest,
) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.git.sanitized-fork-terminal-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(intention.as_bytes())
        .chain_update(predecessor.as_bytes())
        .finalize();
    let mut transaction = [0_u8; 16];
    transaction.copy_from_slice(&digest[..16]);
    transaction
}

pub(crate) fn recover_git_journal_verifier_v1(
    journal: &Journal,
    evidence: GitProtectedClaimEvidenceV1,
) -> Result<GitJournalVerifierV1, ProtectedDomainJournalErrorV1> {
    let (
        validator_attestation,
        current_boot,
        current_boottime,
        boot_attestation,
        mut authenticated_predecessor_boots,
        mut accepted_graphs,
        mut accepted_ancestry,
        mut accepted_validation_reports,
    ) = evidence.into_parts();
    let candidates =
        protected_current_record_candidates_v1::<GitProtectedJournalSchemaV1>(journal)?;
    authenticated_predecessor_boots.sort_unstable();
    accepted_graphs.sort_unstable();
    accepted_ancestry.sort_unstable();
    accepted_validation_reports.sort_unstable();
    if authenticated_predecessor_boots
        .windows(2)
        .chain(accepted_graphs.windows(2))
        .chain(accepted_ancestry.windows(2))
        .chain(accepted_validation_reports.windows(2))
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }

    let mut accepted_records = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() != GitProtectedRecordKindV1::Checkpoint)
        .map(|candidate| candidate.envelope_digest())
        .collect::<Vec<_>>();
    let mut accepted_checkpoints = candidates
        .iter()
        .filter(|candidate| candidate.key().kind() == GitProtectedRecordKindV1::Checkpoint)
        .map(|candidate| candidate.envelope_digest())
        .collect::<Vec<_>>();
    accepted_records.sort_unstable();
    accepted_checkpoints.sort_unstable();
    let authority = protected_git_authority(&candidates);
    GitJournalVerifierV1::from_verified_state(
        authority,
        validator_attestation,
        current_boot,
        current_boottime,
        boot_attestation,
        authenticated_predecessor_boots,
        accepted_graphs,
        accepted_ancestry,
        accepted_validation_reports,
        accepted_records,
        accepted_checkpoints,
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
}

fn protected_git_authority(
    candidates: &[crate::lifecycle::protected_journal_adapter::ProtectedCurrentRecordCandidateV1<
        GitProtectedJournalSchemaV1,
    >],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.git.protected-owner.v1\0")
        .chain_update((candidates.len() as u64).to_be_bytes());
    for candidate in candidates {
        hasher = hasher
            .chain_update((candidate.key().as_bytes().len() as u32).to_be_bytes())
            .chain_update(candidate.key().as_bytes())
            .chain_update(candidate.envelope_digest().as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
