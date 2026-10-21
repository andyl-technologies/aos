//! Shares the actual protected transaction control schedule at compile time.
//!
//! Canonical planning, member encoding and before/after image comparisons stay
//! in their existing DATA helpers. Each real role supplies its private native
//! owner, actual typed final gate and private capability wrappers. There is no
//! externally implementable native trait, function pointer, public success
//! constructor, additional writer, or Domain-Journal facade in this module.
//!
//! The three focused recipes preserve the original short-stage boundaries:
//! before checks and slow preflight, actual final-gated append, exact readback,
//! instance-bound sealing, and retained recovery. Native post ownership and
//! result parking remain with the actual resident caller at the same frontier.

/// Defines the existing private protected commit schedule around real role gates.
///
/// The invocation supplies its concrete private native owner type. Planning,
/// preflight, final append and owed posts still use that owner's actual methods
/// and genuine typed loans. This recipe defines no public native port, callback,
/// success flag or capability constructor. Prepared/Pending/Applied wrappers
/// remain private to the invoking role and retain their original field order.
///
/// An optional `gate = ConcreteGate<'_, ...>` binding preserves the invoking
/// role's genuine borrowed lifetimes in these private method signatures. The
/// one-argument form expands to the unchanged existing Cache gate type. Neither
/// form accepts an implementation, callback, runtime mode or supplied authority.
///
/// The complete returned append result is classified before readback or later
/// checks. A resident caller still parks this complete result in its original
/// before independently owed outer posts, exactly as before the extraction.
#[macro_export]
macro_rules! define_protected_commit_control_v1 {
    ($native:ty) => {
        $crate::define_protected_commit_control_v1!($native, gate = CacheMutationGateV1<'_>);
    };
    ($native:ty, gate = $gate:ty) => {
        fn commit_with_custody(
            &mut self,
            prepared: PreparedDomainTransactionV1<S>,
            mut check: impl FnMut(&$native) -> Result<(), JournalError>,
            mut gate: $gate,
        ) -> Result<DomainCommitOutcomeV1<S>, DomainRetainedCommitFailureV1<S>> {
            let before = self.check_prepared_before_append(&prepared, &mut gate, &mut check);
            if let Err(cause) = before {
                return Err(RetainedCommitFailureV1::BeforeJournalAppend { prepared, cause });
            }
            if let Err(cause) = gate.commit(self.journal, &prepared.data.transaction) {
                return Ok(DomainCommitOutcomeV1::OutcomeUnknown {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    cause,
                });
            }
            if let Err(cause) = validate_expected_values(self.journal, &prepared, true) {
                return Err(RetainedCommitFailureV1::AfterAppendReadback {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    cause,
                });
            }
            if let Err(cause) = check(self.journal) {
                return Ok(DomainCommitOutcomeV1::OutcomeUnknown {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    cause,
                });
            }
            self.applied_retaining(prepared)
                .map(DomainCommitOutcomeV1::Applied)
                .map_err(
                    |(prepared, cause)| RetainedCommitFailureV1::AfterAppendSealing {
                        pending: DomainOutcomeUnknownV1 { prepared },
                        cause,
                    },
                )
        }

        fn check_prepared_before_append(
            &self,
            prepared: &PreparedDomainTransactionV1<S>,
            gate: &mut $gate,
            check: &mut impl FnMut(&$native) -> Result<(), JournalError>,
        ) -> Result<(), ProtectedDomainJournalErrorV1> {
            self.validate_snapshot(&prepared.snapshot)?;
            validate_expected_values(self.journal, prepared, false)?;
            gate.preflight(
                self.journal,
                std::slice::from_ref(&prepared.data.transaction),
            )?;
            check(self.journal)?;
            Ok(())
        }

        /// Appends while borrowing the resident Prepared instead of taking it.
        ///
        /// The caller parks this complete Result before any final owner checks.
        /// An append failure keeps both exact before/after bytes and its native
        /// error in the same resident owner; it is not retry authorization.
        ///
        /// # Errors
        /// Returns the first preappend, append, readback or sealing failure.
        pub(crate) fn commit_resident_prepared(
            &mut self,
            prepared: &PreparedDomainTransactionV1<S>,
            mut gate: $gate,
        ) -> Result<AppliedDomainTransactionV1<S>, ResidentDomainCommitFailureV1> {
            self.check_prepared_before_append(prepared, &mut gate, &mut |_| Ok(()))
                .map_err(ResidentDomainCommitFailureV1::Before)?;
            gate.commit(self.journal, &prepared.data.transaction)
                .map_err(ResidentDomainCommitFailureV1::Append)?;
            validate_expected_values(self.journal, prepared, true)
                .map_err(ResidentDomainCommitFailureV1::Readback)?;
            self.applied_borrowed(prepared)
                .map_err(ResidentDomainCommitFailureV1::Sealing)
        }
    };
}

/// Defines the unchanged private retained-recovery classification schedule.
///
/// Before/after image comparison stays canonical DATA. Only the actual role's
/// replay, same-instance snapshot and native preflight can produce its private
/// retry or applied wrappers; classification supplies no permission to retry an
/// effect. An ordinary comparison may refresh its snapshot only at the existing
/// ordinary branch. A retained gate keeps the original snapshot requirement.
#[macro_export]
macro_rules! define_protected_recovery_control_v1 {
    ($native:ty) => {
        $crate::define_protected_recovery_control_v1!($native, gate = CacheMutationGateV1<'_>);
    };
    ($native:ty, gate = $gate:ty) => {
        /// Classifies the same pending event without reopening a resident writer.
        ///
        /// A before image must still match its original snapshot and pass the same
        /// gate and preflight. Classification is not permission to retry an effect.
        pub(crate) fn recover_retaining_with_cache_gate(
            &self,
            pending: DomainOutcomeUnknownV1<S>,
            mut gate: $gate,
        ) -> DomainRetainedRecoveryV1<S> {
            if let Err(error) = self.replay() {
                return DomainRetainedRecoveryV1::Retryable { pending, error };
            }
            let prepared = pending.prepared;
            let DomainRecoveryImageComparisonDataV1 { before, after } =
                transaction_state::compare_recovery_images_v1(
                    self.journal.historical_read_view_v1(),
                    &prepared.data,
                );
            if after {
                return match self.applied_retaining(prepared) {
                    Ok(applied) => {
                        DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Applied(applied))
                    }
                    Err((prepared, error)) => DomainRetainedRecoveryV1::Retryable {
                        pending: DomainOutcomeUnknownV1 { prepared },
                        error,
                    },
                };
            }
            if before {
                let mut prepared = prepared;
                if matches!(&gate, CacheMutationGateV1::Ordinary) {
                    prepared.snapshot = match self.snapshot() {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            return DomainRetainedRecoveryV1::Retryable {
                                pending: DomainOutcomeUnknownV1 { prepared },
                                error,
                            };
                        }
                    };
                } else if let Err(error) = self.validate_snapshot(&prepared.snapshot) {
                    return DomainRetainedRecoveryV1::Retryable {
                        pending: DomainOutcomeUnknownV1 { prepared },
                        error,
                    };
                }
                if let Err(error) = gate
                    .preflight(
                        self.journal,
                        std::slice::from_ref(&prepared.data.transaction),
                    )
                    .map_err(ProtectedDomainJournalErrorV1::from)
                {
                    return DomainRetainedRecoveryV1::Retryable {
                        pending: DomainOutcomeUnknownV1 { prepared },
                        error,
                    };
                }
                return DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Retry(prepared));
            }
            DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Diverged(DomainOutcomeUnknownV1 {
                prepared,
            }))
        }
    };
}

/// Defines same-instance snapshot and exact postcommit sealing in a private role.
///
/// The invoking role retains its actual instance, validator, native owner and
/// private capability types. Canonical comparison helpers cannot construct
/// these effect-facing wrappers from supplied DATA. Both borrowed and owning
/// sealing preserve their original error and Prepared/Pending custody order.
#[macro_export]
macro_rules! define_protected_sealing_control_v1 {
    ($native:ty) => {
        fn validate_snapshot(
            &self,
            snapshot: &ProtectedDomainSnapshotV1<S>,
        ) -> Result<(), ProtectedDomainJournalErrorV1> {
            let current = self.snapshot()?;
            if !Arc::ptr_eq(&snapshot.instance, &self.instance)
                || snapshot.sequence != current.sequence
                || snapshot.root != current.root
            {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            Ok(())
        }

        fn applied(
            &self,
            prepared: PreparedDomainTransactionV1<S>,
        ) -> Result<AppliedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
            self.applied_borrowed(&prepared)
        }

        fn applied_borrowed(
            &self,
            prepared: &PreparedDomainTransactionV1<S>,
        ) -> Result<AppliedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
            let snapshot = self.snapshot()?;
            let records = postcommit_records(prepared, &self.validator)?;
            let capability = Some(DomainPostcommitCapabilityV1 {
                instance: Arc::clone(&self.instance),
                transaction: prepared.data.digest,
                set_digest: prepared.data.set_digest,
                sequence: snapshot.sequence,
                root: snapshot.root,
                records,
                marker: PhantomData,
            });
            Ok(AppliedDomainTransactionV1 {
                transaction: prepared.data.digest,
                snapshot,
                capability,
            })
        }

        fn applied_retaining(
            &self,
            prepared: PreparedDomainTransactionV1<S>,
        ) -> Result<
            AppliedDomainTransactionV1<S>,
            (
                PreparedDomainTransactionV1<S>,
                ProtectedDomainJournalErrorV1,
            ),
        > {
            let snapshot = match self.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => return Err((prepared, error)),
            };
            let records = match postcommit_records(&prepared, &self.validator) {
                Ok(records) => records,
                Err(error) => return Err((prepared, error)),
            };
            let capability = Some(DomainPostcommitCapabilityV1 {
                instance: Arc::clone(&self.instance),
                transaction: prepared.data.digest,
                set_digest: prepared.data.set_digest,
                sequence: snapshot.sequence,
                root: snapshot.root,
                records,
                marker: PhantomData,
            });
            Ok(AppliedDomainTransactionV1 {
                transaction: prepared.data.digest,
                snapshot,
                capability,
            })
        }
    };
}
