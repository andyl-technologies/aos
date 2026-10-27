//! Owns complete domain capacity admission, recovery, and terminal settlement.
//!
//! These inherent recipes retain the original adapter's Journal loan and purpose
//! guards. Resident token fields and shared postcommit issuance stay in the parent.

use super::{
    DomainCapacityAdmissionCommitOutcomeV1, DomainCapacityAdmissionRecoveryV1,
    DomainCapacityAdmissionUnknownV1, DomainCapacityReservationV1,
    DomainCapacitySettlementCommitOutcomeV1, DomainCapacitySettlementRecoveryV1,
    DomainCapacitySettlementUnknownV1, GlobalCapacityReservationPurposeV1,
    GlobalCapacityReservationRecoveryBindingV1, GlobalCapacityReservationRequestV1, JournalError,
    JournalRecord, JournalTransaction, PhantomData, PreparedCapacityReservedDomainTransactionV1,
    PreparedCapacitySettlementDomainTransactionV1, PreparedDomainTransactionV1,
    ProtectedCapacitySettlementMemberV1, ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1,
    ProtectedDomainSchemaV1, ProtectedReducerPhaseV1, RecordNamespace, aggregate_semantic_phases,
    capacity_request_binds_schema, decode_reducer_payload_with_validator, postcommit_records,
    validate_domain_capacity_lineage_v1, validate_expected_values, values_match,
};

impl<'journal, S: ProtectedDomainSchemaV1> ProtectedDomainJournalV1<'journal, S> {
    /// Joins an exact prepared domain admission to a global capacity reservation.
    ///
    /// The purpose guard validates the complete closed namespace set. Neither
    /// the underlying journal nor the prepared [`JournalTransaction`] leaves
    /// this engine.
    ///
    /// # Errors
    ///
    /// Returns an error for stale domain CAS state, an unbound request digest,
    /// a foreign purpose namespace set, or failed capacity preflight.
    pub fn prepare_capacity_reserved_admission(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        request: GlobalCapacityReservationRequestV1,
    ) -> Result<PreparedCapacityReservedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared, false)?;
        if request.owner_digest != *prepared.data.digest.as_bytes()
            || !capacity_request_binds_schema::<S>(&request)
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.data.transaction, request.purpose)?;

        let transaction_id = *prepared.data.transaction.id();
        let authority = self
            .journal
            .claim_global_capacity_reservation_authority(request.purpose)?;
        let reservation =
            authority.prepare_global_capacity_reservation_v1(request, transaction_id)?;
        let reservation_id = reservation.reservation_id();
        let combined = capacity_admission_transaction(&prepared.data.transaction, reservation.record())?;
        let preflight =
            authority.preflight_global_capacity_reservation_v1(&reservation, &combined)?;

        Ok(PreparedCapacityReservedDomainTransactionV1 {
            prepared,
            combined,
            request,
            reservation_id,
            reservation,
            preflight,
        })
    }

    /// Commits an exact domain admission and capacity record atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the domain snapshot or predecessor values changed.
    /// Durability failures are returned as retained outcome-unknown state.
    pub fn commit_capacity_reserved_admission(
        &mut self,
        prepared: PreparedCapacityReservedDomainTransactionV1<S>,
    ) -> Result<DomainCapacityAdmissionCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared.prepared, false)?;
        if prepared.request.owner_digest != *prepared.prepared.data.digest.as_bytes()
            || !capacity_request_binds_schema::<S>(&prepared.request)
            || prepared.reservation_id != prepared.reservation.reservation_id()
            || capacity_admission_transaction(
                &prepared.prepared.data.transaction,
                prepared.reservation.record(),
            )? != prepared.combined
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.prepared.data.transaction, prepared.request.purpose)?;

        let PreparedCapacityReservedDomainTransactionV1 {
            prepared: domain,
            combined,
            request,
            reservation_id,
            reservation,
            preflight,
        } = prepared;
        let commit = {
            let mut authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.commit_global_capacity_reservation_v1(&preflight, reservation, &combined)
        };
        let (_, reservation) = match commit {
            Ok(applied) => applied,
            Err(cause) => {
                return Ok(DomainCapacityAdmissionCommitOutcomeV1::OutcomeUnknown {
                    pending: DomainCapacityAdmissionUnknownV1 {
                        prepared: domain,
                        combined,
                        request,
                        reservation_id,
                    },
                    cause,
                });
            }
        };
        if validate_expected_values(self.journal, &domain, true).is_err()
            || !reservation.matches_request(&request, *domain.data.transaction.id())
            || reservation.reservation_id() != reservation_id
        {
            return Ok(DomainCapacityAdmissionCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacityAdmissionUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    reservation_id,
                },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        let admission_transaction_id = *domain.data.transaction.id();
        let domain = self.applied(domain)?;
        Ok(DomainCapacityAdmissionCommitOutcomeV1::Applied {
            domain,
            reservation: DomainCapacityReservationV1 {
                reservation,
                request,
                admission_transaction_id,
                marker: PhantomData,
            },
        })
    }

    /// Recovers one exact capacity admission after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay or the purpose authority cannot
    /// be validated. Mixed state is retained as [`DomainCapacityAdmissionRecoveryV1::Diverged`].
    pub fn recover_capacity_reserved_admission(
        &mut self,
        pending: DomainCapacityAdmissionUnknownV1<S>,
    ) -> Result<DomainCapacityAdmissionRecoveryV1<S>, ProtectedDomainJournalErrorV1> {
        self.replay()?;
        let DomainCapacityAdmissionUnknownV1 {
            mut prepared,
            combined,
            request,
            reservation_id,
        } = pending;
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        let admission_transaction_id = *prepared.data.transaction.id();
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        if after {
            let reservation = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                authority.recover_global_capacity_reservation_v1(reservation_id)
            };
            if let Ok(reservation) = reservation {
                if reservation.matches_request(&request, admission_transaction_id) {
                    let domain = self.applied(prepared)?;
                    return Ok(DomainCapacityAdmissionRecoveryV1::Applied {
                        domain,
                        reservation: DomainCapacityReservationV1 {
                            reservation,
                            request,
                            admission_transaction_id,
                            marker: PhantomData,
                        },
                    });
                }
            }
            return Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
                DomainCapacityAdmissionUnknownV1 {
                    prepared,
                    combined,
                    request,
                    reservation_id,
                },
            ));
        }

        if before {
            prepared.snapshot = self.snapshot()?;
            let (reservation, preflight) = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                let reservation = authority
                    .prepare_global_capacity_reservation_v1(request, admission_transaction_id)?;
                if reservation.reservation_id() != reservation_id
                    || capacity_admission_transaction(&prepared.data.transaction, reservation.record())?
                        != combined
                {
                    return Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
                        DomainCapacityAdmissionUnknownV1 {
                            prepared,
                            combined,
                            request,
                            reservation_id,
                        },
                    ));
                }
                let preflight =
                    authority.preflight_global_capacity_reservation_v1(&reservation, &combined)?;
                (reservation, preflight)
            };
            return Ok(DomainCapacityAdmissionRecoveryV1::Retry(
                PreparedCapacityReservedDomainTransactionV1 {
                    prepared,
                    combined,
                    request,
                    reservation_id,
                    reservation,
                    preflight,
                },
            ));
        }

        Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
            DomainCapacityAdmissionUnknownV1 {
                prepared,
                combined,
                request,
                reservation_id,
            },
        ))
    }

    /// Recovers one move-only capacity authority from an exact durable identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless the retained reservation exactly matches the
    /// request, admission transaction, domain binding, and purpose authority.
    pub fn recover_domain_capacity_reservation(
        &mut self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
        reservation_id: [u8; 32],
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let reservation = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.recover_global_capacity_reservation_v1(reservation_id)?
        };
        if !reservation.matches_request(&request, admission_transaction_id) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Recovers capacity by its complete deterministic request binding.
    ///
    /// This endpoint avoids requiring a reducer to persist the reservation ID,
    /// which would otherwise form a cycle with the domain transaction digest.
    ///
    /// # Errors
    ///
    /// Returns an error unless exactly one current reservation matches the
    /// request and admission transaction under the closed purpose authority.
    pub fn recover_domain_capacity_reservation_for_request(
        &mut self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        if !capacity_request_binds_schema::<S>(&request) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let reservation_ids = self
            .journal
            .records(RecordNamespace::GlobalCapacityReservation)
            .filter_map(|(key, _)| key.get(key.len().checked_sub(32)?..)?.try_into().ok())
            .collect::<Vec<[u8; 32]>>();
        let mut matching = None;
        let authority = self
            .journal
            .claim_global_capacity_reservation_authority(request.purpose)?;
        for reservation_id in reservation_ids {
            let reservation = match authority.recover_global_capacity_reservation_v1(reservation_id)
            {
                Ok(reservation) => reservation,
                Err(JournalError::ForeignAuthorityNamespace) => continue,
                Err(error) => return Err(error.into()),
            };
            if !reservation.matches_request(&request, admission_transaction_id) {
                continue;
            }
            if matching.replace(reservation).is_some() {
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
            }
        }
        let reservation = matching.ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Recovers the unique domain reservation from stable lineage alone.
    ///
    /// Enumeration and authentication of namespace 46 stay inside the sealed
    /// purpose guard. The returned request and admission transaction are those
    /// retained by the unique canonical record, never caller-shaped values.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or multiple matches, malformed provenance, a
    /// foreign purpose, or a request that does not bind this domain schema.
    pub fn recover_unique_domain_capacity_reservation_by_binding(
        &mut self,
        binding: GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        let reservation = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(binding.purpose)?;
            authority.recover_unique_global_capacity_reservation_v1(&binding)?
        };
        let request = reservation.request();
        let admission_transaction_id = reservation.admission_transaction_id();
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation.reservation_id(),
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Joins an exact terminal domain transaction to its reservation deletion.
    ///
    /// # Errors
    ///
    /// Returns an error for stale domain CAS, nonterminal semantic state,
    /// substituted reservation binding, foreign namespaces, or capacity bounds.
    pub fn prepare_capacity_settlement(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        reservation: DomainCapacityReservationV1<S>,
    ) -> Result<PreparedCapacitySettlementDomainTransactionV1<S>, ProtectedDomainJournalErrorV1>
    {
        self.validate_snapshot(&prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared, false)?;
        let phases = postcommit_records(&prepared, &self.validator)?;
        if aggregate_semantic_phases(&phases.iter().map(|record| record.phase()).collect::<Vec<_>>())
            != ProtectedReducerPhaseV1::Terminal
            || !reservation
                .reservation
                .matches_request(&reservation.request, reservation.admission_transaction_id)
            || !capacity_request_binds_schema::<S>(&reservation.request)
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let decoded = phases
            .iter()
            .map(|record| {
                decode_reducer_payload_with_validator::<S>(
                    record.envelope().key(),
                    record.envelope().payload(),
                    &self.validator,
                )
                .map_err(ProtectedDomainJournalErrorV1::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let members = phases
            .iter()
            .zip(&decoded)
            .map(|(record, payload)| {
                ProtectedCapacitySettlementMemberV1::from_unvalidated_data(
                    record.envelope().key().kind(),
                    record.envelope().key().identity(),
                    payload.body(),
                )
            })
            .collect::<Vec<_>>();
        if !S::validates_capacity_settlement(
            &reservation.request,
            reservation.admission_transaction_id,
            &members,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.data.transaction, reservation.request.purpose)?;

        let combined = capacity_settlement_transaction(
            &prepared.data.transaction,
            reservation.reservation.settlement_record(),
        )?;
        let preflight = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(reservation.request.purpose)?;
            authority.preflight_reserved_terminal_v1(&reservation.reservation, &combined)?
        };
        Ok(PreparedCapacitySettlementDomainTransactionV1 {
            prepared,
            combined,
            reservation,
            preflight,
        })
    }

    /// Commits one exact terminal branch and releases its retained capacity.
    ///
    /// # Errors
    ///
    /// Returns an error when the domain snapshot or predecessor values changed.
    /// Durability failure retains exact outcome-unknown settlement state.
    pub fn commit_capacity_settlement(
        &mut self,
        prepared: PreparedCapacitySettlementDomainTransactionV1<S>,
    ) -> Result<DomainCapacitySettlementCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared.prepared, false)?;
        let PreparedCapacitySettlementDomainTransactionV1 {
            prepared: domain,
            combined,
            reservation,
            preflight,
        } = prepared;
        let DomainCapacityReservationV1 {
            reservation: raw_reservation,
            request,
            admission_transaction_id,
            marker: _,
        } = reservation;
        let reservation_id = raw_reservation.reservation_id();
        let commit = {
            let mut authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.commit_reserved_terminal_v1(&preflight, raw_reservation, &combined)
        };
        if let Err(cause) = commit {
            return Ok(DomainCapacitySettlementCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacitySettlementUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    admission_transaction_id,
                    reservation_id,
                },
                cause,
            });
        }
        if validate_expected_values(self.journal, &domain, true).is_err() {
            return Ok(DomainCapacitySettlementCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacitySettlementUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    admission_transaction_id,
                    reservation_id,
                },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        self.applied(domain)
            .map(DomainCapacitySettlementCommitOutcomeV1::Applied)
    }

    /// Recovers one ambiguous capacity settlement after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay or the purpose authority fails.
    pub fn recover_capacity_settlement(
        &mut self,
        pending: DomainCapacitySettlementUnknownV1<S>,
    ) -> Result<DomainCapacitySettlementRecoveryV1<S>, ProtectedDomainJournalErrorV1> {
        self.replay()?;
        let DomainCapacitySettlementUnknownV1 {
            mut prepared,
            combined,
            request,
            admission_transaction_id,
            reservation_id,
        } = pending;
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        if after {
            let reservation = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                authority.lookup_global_capacity_reservation_v1(reservation_id)?
            };
            if reservation.is_none() {
                return self
                    .applied(prepared)
                    .map(DomainCapacitySettlementRecoveryV1::Applied);
            }
        } else if before {
            prepared.snapshot = self.snapshot()?;
            let reservation = self.recover_domain_capacity_reservation(
                request,
                admission_transaction_id,
                reservation_id,
            )?;
            if capacity_settlement_transaction(
                &prepared.data.transaction,
                reservation.reservation.settlement_record(),
            )? == combined
            {
                let preflight = {
                    let authority = self
                        .journal
                        .claim_global_capacity_reservation_authority(request.purpose)?;
                    authority.preflight_reserved_terminal_v1(&reservation.reservation, &combined)?
                };
                return Ok(DomainCapacitySettlementRecoveryV1::Retry(
                    PreparedCapacitySettlementDomainTransactionV1 {
                        prepared,
                        combined,
                        reservation,
                        preflight,
                    },
                ));
            }
        }

        Ok(DomainCapacitySettlementRecoveryV1::Diverged(
            DomainCapacitySettlementUnknownV1 {
                prepared,
                combined,
                request,
                admission_transaction_id,
                reservation_id,
            },
        ))
    }
}

pub(super) fn capacity_admission_transaction(
    domain: &JournalTransaction,
    reservation: &JournalRecord,
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_broker::domain_transaction_custody::capacity::capacity_admission_transaction(
        domain, reservation,
    ).map_err(JournalError::from)
}

pub(super) fn validate_capacity_domain_shape(
    transaction: &JournalTransaction,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<(), JournalError> {
    aos_sandbox_broker::domain_transaction_custody::capacity::validate_capacity_domain_shape(
        transaction, purpose,
    ).map_err(JournalError::from)
}

pub(super) fn capacity_settlement_transaction(
    domain: &JournalTransaction,
    settlement: JournalRecord,
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_broker::domain_transaction_custody::capacity::capacity_settlement_transaction(
        domain, settlement,
    ).map_err(JournalError::from)
}
