//! Lends the actual Source provider writer through its existing closed purposes.
//!
//! Snapshots and preflight retain the same allocation and exact cut. Readonly
//! and original scopes cannot use generic mutation or legacy capacity grants;
//! the separate original writer keeps its complete replay/readback gates.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_journal::protected_storage::resolve_protected_directory_from_root;
use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1,
};

use super::semantic_append::PreflightScope;
use super::{
    CommitResult, FixedSourceProviderJournalHandoffV1, GlobalCapacityReservationV1, JournalError,
    JournalTransaction, PreparedGlobalCapacityReservationV1, ProtectedAuthorityScope,
    ProtectedJournalAuthority, ProtectedJournalPreflight, ProtectedJournalSnapshot,
    RecordNamespace, authority_preflight_digest, capacity_reservation, original, readonly,
};

impl ProtectedJournalAuthority<'_> {
    /// Checks this held root-owned writer against its fixed physical names.
    ///
    /// The existing exclusive claim stays borrowed while the journal opener
    /// re-resolves its directory and compares the journal and lock inodes.
    /// This observation grants no authority and changes neither namespace nor
    /// claim scope. It does not fence a privileged rename after the check.
    ///
    /// # Errors
    ///
    /// Rejects a claim that cannot perform generic authority reads, changed
    /// root/directory/journal/lock names, or an unhealthy protected writer.
    pub fn validate_held_root_owned_at(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
    ) -> Result<(), JournalError> {
        self.journal.validate_held_root_owned_at(directory, name)
    }

    /// Validates the fixed provider namespace-41 storage boundary.
    ///
    /// This purpose check compares the retained protected directory descriptor
    /// with a fresh no-symlink resolution of the compiled-in provider state
    /// root and requires the exact journal basename. It grants no record or
    /// mutation authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the current dedicated namespace-41
    /// claim over `/var/lib/aos/source-provider/provider.journal`.
    #[doc(hidden)]
    pub fn validate_fixed_source_provider_storage(&self) -> Result<(), JournalError> {
        self.validate_source_provider_authority()?;
        self.validate_fixed_storage("/var/lib/aos/source-provider", "provider.journal")
    }

    /// Validates the fixed Provider native-hold challenge journal location.
    ///
    /// The dedicated journal shares namespace 41 but has its own exclusive
    /// lock and format. Its retained directory must still be the protected
    /// Provider state root at each authority-bound read or mutation.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the current dedicated namespace-41
    /// claim over the fixed native-hold challenge journal.
    #[doc(hidden)]
    pub fn validate_fixed_source_provider_hold_challenge_storage(
        &self,
    ) -> Result<(), JournalError> {
        self.validate_source_provider_authority()?;
        self.validate_fixed_storage(
            "/var/lib/aos/source-provider",
            "native-hold-challenges.journal",
        )
    }

    fn validate_fixed_storage(&self, directory: &str, name: &str) -> Result<(), JournalError> {
        let retained = self
            .journal
            .native_view()
            .protected_view()
            .ok_or(JournalError::ProtectedBoundary)?;
        if retained.expected_uid() != 0 || retained.name() != name {
            return Err(JournalError::ProtectedBoundary);
        }
        let fixed = resolve_protected_directory_from_root::<JournalError>(Path::new(directory), 0)?;
        retained.require_opened_directory::<JournalError>(&fixed)?;
        Ok(())
    }

    /// Mints one move-only handoff from the exact current fixed provider claim.
    ///
    /// # Errors
    ///
    /// Returns an error unless the fixed path, basename, namespace, journal
    /// instance, and current sequence are all protected and current.
    #[doc(hidden)]
    pub fn fixed_source_provider_session_handoff(
        &self,
    ) -> Result<FixedSourceProviderJournalHandoffV1<'_, '_>, JournalError> {
        self.validate_fixed_source_provider_storage()?;
        Ok(FixedSourceProviderJournalHandoffV1 {
            authority: self,
            sequence: self.journal.native_view().next_sequence(),
        })
    }

    /// Revalidates a fixed provider session handoff before it is consumed.
    ///
    /// # Errors
    ///
    /// Returns an error after another append, compaction, reopen, or owner
    /// replacement, or for a handoff minted by another journal.
    #[doc(hidden)]
    pub fn validate_fixed_source_provider_session_handoff(
        &self,
        handoff: &FixedSourceProviderJournalHandoffV1<'_, '_>,
    ) -> Result<(), JournalError> {
        if self.scope == ProtectedAuthorityScope::SourceOriginalNativeV5 {
            original::writer::require_fixed(self.journal)?;
        } else if self.scope == ProtectedAuthorityScope::SourceProviderHeldReadOnly {
            readonly::validate_current_authority(self)?;
        } else {
            self.validate_fixed_source_provider_storage()?;
        }
        if !core::ptr::eq(handoff.authority, self)
            || handoff.sequence != self.journal.native_view().next_sequence()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Validates this guard as the exact namespace-41 provider authority.
    ///
    /// This purpose check is public only so the provider owner and independent
    /// security custody can reject a generic protected guard before decoding
    /// `AOSSPL01`. It grants no record, mutation, or snapshot authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is healthy, purpose scoped,
    /// and names [`RecordNamespace::SourceProviderAuthority`].
    #[doc(hidden)]
    pub fn validate_source_provider_authority(&self) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if self.namespace != RecordNamespace::SourceProviderAuthority
            || !matches!(
                self.scope,
                ProtectedAuthorityScope::SingleNamespace
                    | ProtectedAuthorityScope::SourceProviderNativeTerminal
            )
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Validates an exact current namespace-41 snapshot and guard.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is the dedicated namespace-41 scope
    /// and the snapshot has the same journal instance, scope, and sequence.
    #[doc(hidden)]
    pub fn validate_source_provider_authority_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_source_provider_authority()?;
        self.validate_snapshot(snapshot)
    }

    /// Returns the current authority value for a logical key.
    ///
    /// The returned value borrows this guard, so it cannot remain live across a
    /// commit or another mutable authority operation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// or [`JournalError::ProtectedBoundary`] if retained protected-open
    /// provenance is absent.
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.get(self.namespace, key))
    }

    /// Iterates current authority records by bytewise key.
    ///
    /// The iterator borrows this guard, so it cannot remain live across a
    /// commit or another mutable authority operation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// or [`JournalError::ProtectedBoundary`] if retained protected-open
    /// provenance is absent.
    pub fn records(&self) -> Result<impl Iterator<Item = (&[u8], &[u8])>, JournalError> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.records(self.namespace))
    }

    /// Reports whether current authority contains no materialized records.
    ///
    /// This supports fail-closed initialization of a dedicated authority
    /// journal without treating diagnostic state from a poisoned handle as
    /// authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// or [`JournalError::ProtectedBoundary`] if retained protected-open
    /// provenance is absent.
    pub fn is_materialized_empty(&self) -> Result<bool, JournalError> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.is_materialized_empty())
    }

    /// Captures an opaque token for the current authority snapshot.
    ///
    /// The token carries no authority by itself. Consumers must validate it
    /// immediately before an effect that depends on state copied from this
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// or [`JournalError::ProtectedBoundary`] if retained protected-open
    /// provenance is absent.
    pub fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.journal.ensure_protected_authority()?;
        Ok(self.current_snapshot())
    }

    /// Validates a snapshot token immediately before an authority-bound effect.
    ///
    /// Validation checks journal health, the exact in-memory journal instance,
    /// the claimed namespace, and the current sequence. A successful check is
    /// therefore invalidated by every intervening commit.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// [`JournalError::ProtectedBoundary`] when this journal lacks retained
    /// protected-open provenance, or [`JournalError::StaleAuthoritySnapshot`]
    /// when `snapshot` belongs to another journal or namespace or its sequence
    /// is no longer current. Read-only Source guards return
    /// [`JournalError::ForeignAuthorityNamespace`] without granting an effect.
    pub fn validate_snapshot_for_effect(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        if self.scope == ProtectedAuthorityScope::SourceProviderHeldReadOnly {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        self.journal.ensure_protected_authority()?;
        self.validate_snapshot(snapshot)
    }

    /// Validates a preflight token immediately before its dependent effect.
    ///
    /// Validation checks journal health, the exact in-memory journal instance,
    /// the claimed namespace, the current sequence, and the exact ordered
    /// transaction contents supplied to preflight. It fails after any
    /// intervening commit, including one made through this guard.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// [`JournalError::ProtectedBoundary`] when this journal lacks retained
    /// protected-open provenance,
    /// [`JournalError::ForeignAuthorityNamespace`] when any supplied
    /// transaction record belongs to another namespace, or
    /// [`JournalError::StaleAuthoritySnapshot`] when `preflight` belongs to
    /// another journal or namespace or its sequence is no longer current.
    /// Returns
    /// [`JournalError::AuthorityPreflightMismatch`] when `transactions` differ
    /// from the preflighted sequence.
    pub fn validate_preflight_for_effect(
        &self,
        preflight: &ProtectedJournalPreflight,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        self.validate_generic_authority_mutation()?;
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespaces(transactions)?;
        self.validate_snapshot(&preflight.snapshot)?;
        if preflight.transaction_digest != authority_preflight_digest(transactions) {
            return Err(JournalError::AuthorityPreflightMismatch);
        }

        Ok(())
    }

    /// Appends and synchronously commits one authority transaction.
    ///
    /// Every record must belong to the namespace claimed by this guard. A
    /// durability failure poisons the underlying journal; every subsequent
    /// operation through this guard will then fail its health check.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] if protected current authority is unavailable,
    /// transaction validation fails, or the durable append cannot complete.
    pub fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.validate_generic_authority_mutation()?;
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespace(transaction)?;
        self.journal.commit(transaction)
    }

    /// Prepares capacity reservation bound to this protected owner namespace.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request names this exact single-namespace
    /// authority and all durable reservation fields and bounds are valid.
    pub fn prepare_global_capacity_reservation_v1(
        &self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> Result<PreparedGlobalCapacityReservationV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        if request.purpose != purpose || request.owner_namespace != self.namespace {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        self.journal
            .prepare_global_capacity_reservation_v1(request, admission_transaction_id)
    }

    /// Preflights one owner admission transaction and its exact capacity record.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign record, a different reservation record or
    /// transaction ID, or any ordinary or outstanding-capacity bound failure.
    pub fn preflight_global_capacity_reservation_v1(
        &self,
        prepared: &PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        let purpose = self.validate_capacity_transaction_namespaces(transaction)?;
        if prepared.request.purpose != purpose
            || prepared.request.owner_namespace != self.namespace
            || transaction.id() != &prepared.admission_transaction_id
            || transaction
                .records()
                .iter()
                .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
                .ne([prepared.record()])
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        self.journal.preflight_in_scope(
            std::slice::from_ref(transaction),
            PreflightScope {
                allow_capacity_records: true,
                ..PreflightScope::default()
            },
        )?;
        Ok(ProtectedJournalPreflight {
            snapshot: self.current_snapshot(),
            transaction_digest: authority_preflight_digest(std::slice::from_ref(transaction)),
        })
    }

    /// Atomically commits owner admission and its exact capacity reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when the preflight is stale, admission differs, or the
    /// durable append cannot preserve every outstanding reservation.
    pub fn commit_global_capacity_reservation_v1(
        &mut self,
        preflight: &ProtectedJournalPreflight,
        prepared: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<(CommitResult, GlobalCapacityReservationV1), JournalError> {
        let purpose = self.validate_capacity_transaction_namespaces(transaction)?;
        self.validate_snapshot(&preflight.snapshot)?;
        if preflight.transaction_digest
            != authority_preflight_digest(std::slice::from_ref(transaction))
            || prepared.request.purpose != purpose
            || prepared.request.owner_namespace != self.namespace
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        self.journal
            .commit_global_capacity_reservation_v1(prepared, transaction)
    }

    /// Recovers one exact owner-bound capacity settlement authority after replay.
    ///
    /// # Errors
    ///
    /// Returns an error unless the retained reservation is canonical and owned
    /// by this exact protected namespace.
    pub fn recover_global_capacity_reservation_v1(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        let reservation = self
            .journal
            .recover_global_capacity_reservation_v1(reservation_id)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(reservation)
    }

    /// Looks up one exact owner-bound capacity reservation after replay.
    ///
    /// `Ok(None)` is an authenticated absence. Malformed records, replay
    /// provenance failures, and authority failures remain errors and must not
    /// be interpreted as absence.
    ///
    /// # Errors
    ///
    /// Returns an error unless the purpose authority and every retained
    /// namespace-46 record involved in the lookup remain valid.
    pub fn lookup_global_capacity_reservation_v1(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<Option<GlobalCapacityReservationV1>, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        let reservation = self
            .journal
            .lookup_global_capacity_reservation_v1(reservation_id)?;
        let Some(reservation) = reservation else {
            return Ok(None);
        };
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(Some(reservation))
    }

    /// Validates the complete retained reservation set for this purpose owner.
    ///
    /// This closes cold replay over namespace 46 without exposing reservation
    /// values as caller-mintable authority. Every retained record is decoded
    /// and provenance-checked before its identity is compared with `expected`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, foreign, duplicated, missing, or orphan
    /// reservations, or when protected journal currentness is unavailable.
    pub fn validate_global_capacity_reservation_set_v1(
        &self,
        expected: &BTreeSet<[u8; 32]>,
    ) -> Result<(), JournalError> {
        let purpose = self.validate_capacity_authority()?;
        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_reservations(
            self.journal.native_view().state(),
        )
        .map_err(JournalError::from)?;
        let mut retained = BTreeSet::new();
        for (key, value) in self
            .journal
            .records(RecordNamespace::GlobalCapacityReservation)
        {
            let (request, _admission_transaction, reservation_id) =
                capacity_reservation::decode_reservation(value)?;
            if key != capacity_reservation::reservation_key(reservation_id).as_slice()
                || request.purpose != purpose
                || request.owner_namespace != self.namespace
                || !retained.insert(reservation_id)
            {
                return Err(JournalError::MalformedRecord(
                    "capacity reservation set is not canonical",
                ));
            }
        }
        if &retained != expected {
            return Err(JournalError::MalformedRecord(
                "capacity reservation set differs from protected owners",
            ));
        }
        Ok(())
    }

    /// Recovers one reservation from its stable binding and protected record.
    ///
    /// The caller does not supply the original owner digest or admission
    /// transaction ID. Both are decoded from the canonical namespace-46 record
    /// and authenticated by replay provenance before the complete stable
    /// binding is compared.
    ///
    /// # Errors
    ///
    /// Returns an error unless the reservation is current, canonical, owned by
    /// this purpose guard, and exactly matches every supplied stable field.
    pub fn recover_global_capacity_reservation_by_binding_v1(
        &self,
        reservation_id: [u8; 32],
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        if binding.purpose != purpose {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let reservation = self
            .journal
            .recover_global_capacity_reservation_v1(reservation_id)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
            || !reservation.matches_recovery_binding(binding)
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        Ok(reservation)
    }

    /// Recovers the unique reservation matching a complete stable binding.
    ///
    /// Namespace-46 enumeration remains inside this sealed purpose guard. Every
    /// record is canonically decoded and replay-provenanced; zero or multiple
    /// stable matches fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign purpose, malformed retained record, or
    /// when the binding has anything other than one exact current match.
    pub fn recover_unique_global_capacity_reservation_v1(
        &self,
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        if binding.purpose != purpose {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let reservation = self
            .journal
            .recover_unique_global_capacity_reservation_v1(binding)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(reservation)
    }

    /// Preflights an exact terminal or poison transaction against held capacity.
    ///
    /// # Errors
    ///
    /// Returns an error unless the reservation is current, its sole deletion is
    /// present, all other records belong to the owner, and one retained branch fits.
    pub fn preflight_reserved_terminal_v1(
        &self,
        reservation: &GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        let purpose = self.validate_capacity_transaction_namespaces(transaction)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        capacity_reservation::validate_settlement_shape(self.journal, reservation, transaction)?;
        self.journal.preflight_in_scope(
            std::slice::from_ref(transaction),
            PreflightScope {
                settling_reservation: Some(reservation.reservation_id),
                allow_capacity_records: true,
                ..PreflightScope::default()
            },
        )?;
        Ok(ProtectedJournalPreflight {
            snapshot: self.current_snapshot(),
            transaction_digest: authority_preflight_digest(std::slice::from_ref(transaction)),
        })
    }

    /// Commits one preflighted terminal branch and consumes its reservation.
    ///
    /// # Errors
    ///
    /// Returns an error for stale preflight, altered records, foreign ownership,
    /// exceeded retained branch bounds, or an ambiguous durable append.
    pub fn commit_reserved_terminal_v1(
        &mut self,
        preflight: &ProtectedJournalPreflight,
        reservation: GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        let purpose = self.validate_capacity_transaction_namespaces(transaction)?;
        self.validate_snapshot(&preflight.snapshot)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
            || preflight.transaction_digest
                != authority_preflight_digest(std::slice::from_ref(transaction))
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        self.journal
            .settle_global_capacity_reservation_v1(reservation, transaction)
    }

    pub(super) fn current_snapshot(&self) -> ProtectedJournalSnapshot {
        ProtectedJournalSnapshot {
            instance: Arc::clone(&self.journal.authority_instance),
            namespace: self.namespace,
            sequence: self.journal.snapshot_sequence(),
            scope: self.scope,
        }
    }

    pub(super) fn validate_snapshot(&self, snapshot: &ProtectedJournalSnapshot) -> Result<(), JournalError> {
        if !Arc::ptr_eq(&self.journal.authority_instance, &snapshot.instance)
            || snapshot.namespace != self.namespace
            || snapshot.sequence != self.journal.snapshot_sequence()
            || snapshot.scope != self.scope
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        Ok(())
    }

    fn validate_transaction_namespaces(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        for transaction in transactions {
            self.validate_transaction_namespace(transaction)?;
        }

        Ok(())
    }

    fn validate_transaction_namespace(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if transaction
            .records()
            .iter()
            .any(|record| record.namespace() != self.namespace)
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }

        Ok(())
    }

    /// Preflights exact same-namespace Source transactions without granting IO.
    ///
    /// # Errors
    /// Refuses a readonly/original mutation route, unhealthy protected custody,
    /// foreign rows, or any unchanged transaction, capacity or journal bound.
    pub fn preflight_transactions(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        self.validate_generic_authority_mutation()?;
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespaces(transactions)?;
        self.journal.preflight_transactions(transactions)?;
        Ok(ProtectedJournalPreflight {
            snapshot: self.current_snapshot(),
            transaction_digest: authority_preflight_digest(transactions),
        })
    }

    fn validate_capacity_transaction_namespaces(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<GlobalCapacityReservationPurposeV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        let mut source_provider = false;
        let mut capacity = false;
        for record in transaction.records() {
            if !purpose.permits(record.namespace()) {
                return Err(JournalError::ForeignAuthorityNamespace);
            }
            match record.namespace() {
                RecordNamespace::SourceProviderAuthority => source_provider = true,
                RecordNamespace::GlobalCapacityReservation => capacity = true,
                _ => return Err(JournalError::ForeignAuthorityNamespace),
            }
        }
        if !source_provider || !capacity {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(purpose)
    }

    fn validate_capacity_authority(
        &self,
    ) -> Result<GlobalCapacityReservationPurposeV1, JournalError> {
        self.journal.ensure_protected_authority()?;
        if self.scope != ProtectedAuthorityScope::SourceProviderNativeTerminal
            || self.namespace != RecordNamespace::SourceProviderAuthority
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal)
    }

    fn validate_generic_authority_mutation(&self) -> Result<(), JournalError> {
        if !matches!(
            self.scope,
            ProtectedAuthorityScope::SingleNamespace
                | ProtectedAuthorityScope::SourceProviderNativeTerminal
        ) {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }
}
