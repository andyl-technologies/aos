//! Lends the same fixed Mount writer through private finite authority scopes.
//!
//! Snapshots retain the actual original allocation and captured sequence. Neither
//! their comparison fields nor a successful historical decode constructs a loan.

use super::*;
use aos_sandbox_journal::protected_storage::resolve_protected_directory_from_root;

/// Borrows the actual Mount writer for one internally selected protocol.
pub struct ProtectedJournalAuthority<'journal> {
    pub(super) journal: &'journal mut MountJournalV1,
    pub(super) namespace: RecordNamespace,
    pub(super) scope: ProtectedAuthorityScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtectedAuthorityScope {
    SingleNamespace,
    FixedMountSourceAcquisition,
    RootLocalRecoveryKind2,
    RootLocalRecoveryKind5,
    RootOriginalNativeV5,
    RootOriginalInventoryV6,
    MountSourceConsumption,
    MountManagerStartup,
}

/// Retains one observation of the actual writer, purpose and sequence.
#[must_use = "the original snapshot must be checked at its effect boundary"]
pub struct ProtectedJournalSnapshot {
    pub(super) instance: Arc<JournalAuthorityInstance>,
    pub(super) namespace: RecordNamespace,
    pub(super) sequence: u64,
    pub(super) scope: ProtectedAuthorityScope,
}

impl ProtectedJournalSnapshot {
    pub(super) fn duplicate_provenance(&self) -> Self {
        Self {
            instance: Arc::clone(&self.instance),
            namespace: self.namespace,
            sequence: self.sequence,
            scope: self.scope,
        }
    }

    /// Returns the captured sequence as comparison DATA.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Binds exact ordered transaction bytes to an actual protected observation.
#[must_use = "the preflight must be checked before its dependent effect"]
pub struct ProtectedJournalPreflight {
    snapshot: ProtectedJournalSnapshot,
    transaction_digest: [u8; 32],
}

impl MountJournalV1 {
    fn claim_fixed_mount_source_acquisition_authority(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_owner(
            self.native.read_view_v1().state(),
            RecordNamespace::MountSourceAcquisition,
        )
        .map_err(JournalError::from)?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: RecordNamespace::MountSourceAcquisition,
            scope: ProtectedAuthorityScope::FixedMountSourceAcquisition,
        })
    }

    /// Claims the closed journal group used by atomic Mount source consumption.
    ///
    /// Owner reads and ordinary commits remain restricted to namespace 40.
    /// The guard additionally permits its single purpose-built four-PUT edge
    /// over namespaces 40, 39, 3, and 2. Other namespaces already retained by
    /// the broker remain inaccessible through this purpose-limited guard.
    ///
    /// # Errors
    ///
    /// Returns `CanonicalJournalMechanicalErrorV1::ProtectedBoundary` for an unprotected journal,
    /// `CanonicalJournalMechanicalErrorV1::Poisoned` after ambiguous durability.
    #[doc(hidden)]
    pub(crate) fn claim_mount_source_consumption_authority(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_owner(
            self.native.read_view_v1().state(),
            RecordNamespace::MountSourceAcquisition,
        )
        .map_err(JournalError::from)?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: RecordNamespace::MountSourceAcquisition,
            scope: ProtectedAuthorityScope::MountSourceConsumption,
        })
    }

    /// Claims the closed journal group used by Mount-manager startup capture.
    ///
    /// The guard exposes no generic record or transaction operations. Its
    /// purpose-specific implementation reads only namespaces 45, 40, 39, and
    /// 2, and may append only one fully derived namespace-45 capture record.
    /// Other broker namespaces remain inaccessible through the guard.
    ///
    /// # Errors
    ///
    /// Returns `CanonicalJournalMechanicalErrorV1::ProtectedBoundary` for an unprotected journal,
    /// or `CanonicalJournalMechanicalErrorV1::Poisoned` after ambiguous durability.
    #[doc(hidden)]
    pub(crate) fn claim_mount_manager_startup_authority(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_owner(
            self.native.read_view_v1().state(),
            RecordNamespace::MountSourceAcquisition,
        )
        .map_err(JournalError::from)?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: RecordNamespace::MountManagerStartupAuthority,
            scope: ProtectedAuthorityScope::MountManagerStartup,
        })
    }
}

/// Lends the exact fixed Mount namespace-40 owner without allowing it to escape.
#[must_use = "the fixed Mount source authority must remain owner-scoped"]
pub struct MountSourceAcquisitionJournalAuthorityV2<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

impl core::fmt::Debug for MountSourceAcquisitionJournalAuthorityV2<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MountSourceAcquisitionJournalAuthorityV2([protected authority])")
    }
}

impl<'journal> MountSourceAcquisitionJournalAuthorityV2<'journal> {
    pub(crate) fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        Ok(Self {
            authority: journal.claim_fixed_mount_source_acquisition_authority()?,
        })
    }

    /// Runs one operation with a nonescaping exact fixed namespace-40 claim.
    ///
    /// The higher-ranked borrow prevents the raw claim, any borrowed record,
    /// or a security session facade tied to it from surviving this call.
    #[doc(hidden)]
    pub fn with_authority<R>(
        &mut self,
        operation: impl for<'borrow> FnOnce(&'borrow mut ProtectedJournalAuthority<'journal>) -> R,
    ) -> R {
        operation(&mut self.authority)
    }
}

impl ProtectedJournalAuthority<'_> {
    /// Rechecks this purpose guard's same held root-owned writer and names.
    pub(super) fn validate_held_root_owned_at(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
    ) -> Result<(), JournalError> {
        self.validate_generic_authority_read()?;
        self.journal.validate_held_root_owned_at(directory, name)
    }

    fn validate_fixed_storage(&self, directory: &str, name: &str) -> Result<(), JournalError> {
        let retained =
            self.journal
                .native
                .read_view_v1()
                .protected_view()
                .ok_or(JournalError::Mechanical(
                    crate::journal::MechanicalError::ProtectedBoundary,
                ))?;
        if retained.expected_uid() != 0 || retained.name() != name {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
        }
        let fixed = resolve_protected_directory_from_root::<crate::journal::JournalError>(
            Path::new(directory),
            0,
        )?;
        retained.require_opened_directory::<JournalError>(&fixed)?;
        Ok(())
    }

    /// Validates this guard as the exact namespace-40 Mount source authority.
    ///
    /// This purpose check is public only so security custody in another crate
    /// can reject a generic protected guard before interpreting `AOSMSA02`
    /// bytes. It grants no record, mutation, or snapshot authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is healthy and names namespace 40.
    #[doc(hidden)]
    pub fn validate_mount_source_acquisition_authority(&self) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if !matches!(
            (self.namespace, self.scope),
            (
                RecordNamespace::MountSourceAcquisition,
                ProtectedAuthorityScope::SingleNamespace
                    | ProtectedAuthorityScope::FixedMountSourceAcquisition
                    | ProtectedAuthorityScope::RootLocalRecoveryKind2
                    | ProtectedAuthorityScope::RootLocalRecoveryKind5
                    | ProtectedAuthorityScope::RootOriginalNativeV5
                    | ProtectedAuthorityScope::RootOriginalInventoryV6
                    | ProtectedAuthorityScope::MountSourceConsumption
            ) | (
                RecordNamespace::MountManagerStartupAuthority,
                ProtectedAuthorityScope::MountManagerStartup
            )
        ) {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::ForeignAuthorityNamespace,
            ));
        }
        self.validate_fixed_storage("/var/lib/aos/sandbox-mount", "mount.journal")
    }

    /// Rejoins the same fixed Source owner before observing its NEW-effect denial.
    ///
    /// This is a negative-only observation. An unselected result does not
    /// replace any original Session, graph, request, clock or mutation check.
    ///
    /// # Errors
    /// Rejects another purpose, changed names or an unhealthy original writer.
    #[doc(hidden)]
    pub fn mount_source_git_coverage_denies_new_v1(&self) -> Result<bool, JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        Ok(self.journal.mount_git_coverage_denies_new_v1())
    }

    /// Iterates exact current namespace-40 records through an approved owner or startup scope.
    ///
    /// This method does not expose other namespaces admitted by a purpose guard.
    /// Callers must run the canonical AOSMSA02 graph validator before relying
    /// on any returned bytes.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the sealed namespace-40 owner,
    /// Mount-consumption, or Mount-manager-startup scope.
    #[doc(hidden)]
    pub fn mount_source_acquisition_records(
        &self,
    ) -> Result<impl Iterator<Item = (&[u8], &[u8])>, JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        Ok(self
            .journal
            .records(RecordNamespace::MountSourceAcquisition))
    }

    /// Returns one exact current namespace-40 value through an approved scope.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is an approved namespace-40 owner or
    /// purpose guard.
    #[doc(hidden)]
    pub fn mount_source_acquisition_get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        Ok(self
            .journal
            .get(RecordNamespace::MountSourceAcquisition, key))
    }

    /// Validates the mutation-owning single-namespace AOSMSA02 authority.
    ///
    /// Purpose-scoped composite guards may read namespace 40 for correlation,
    /// but cannot be substituted for the owner that commits row-only or
    /// request/head lifecycle transitions.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is the exact namespace-40 owner scope.
    #[doc(hidden)]
    pub fn validate_mount_source_acquisition_owner_authority(&self) -> Result<(), JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        if self.namespace != RecordNamespace::MountSourceAcquisition
            || !matches!(
                self.scope,
                ProtectedAuthorityScope::SingleNamespace
                    | ProtectedAuthorityScope::FixedMountSourceAcquisition
            )
        {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::ForeignAuthorityNamespace,
            ));
        }
        Ok(())
    }

    /// Reports whether this protected journal generation retained one transaction identity.
    ///
    /// The identity is diagnostic unless the caller also validates the exact
    /// deterministic AOSMSA02 transaction shape and every current record.
    /// Compaction changes the authority instance and removes old provenance.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is the sealed namespace-40 authority.
    #[doc(hidden)]
    pub fn contains_mount_source_acquisition_transaction(
        &self,
        transaction_id: &[u8; 16],
    ) -> Result<bool, JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        Ok(self
            .journal
            .native
            .read_view_v1()
            .transaction_ids()
            .contains(transaction_id))
    }

    /// Validates an exact current namespace-40 snapshot and guard.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard names namespace 40 and the snapshot
    /// has the same journal instance, purpose scope, namespace, and sequence.
    #[doc(hidden)]
    pub fn validate_mount_source_acquisition_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        self.validate_snapshot(snapshot)
    }

    /// Validates this guard as the exact namespace-45 startup authority.
    ///
    /// This sealed purpose check prevents caller-shaped activation metadata in
    /// any other protected namespace from authorizing manager custody or
    /// absence. It grants no descriptor or mutation authority by itself.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is healthy, purpose scoped, and names
    /// [`RecordNamespace::MountManagerStartupAuthority`].
    #[doc(hidden)]
    pub fn validate_mount_manager_startup_authority(&self) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if self.namespace != RecordNamespace::MountManagerStartupAuthority
            || self.scope != ProtectedAuthorityScope::MountManagerStartup
        {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::ForeignAuthorityNamespace,
            ));
        }
        Ok(())
    }

    /// Validates an exact current namespace-45 snapshot and guard.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is the dedicated namespace-45 scope
    /// and the snapshot has the same journal instance, scope, and sequence.
    #[doc(hidden)]
    pub fn validate_mount_manager_startup_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_mount_manager_startup_authority()?;
        self.validate_snapshot(snapshot)
    }

    /// Validates the exact namespace-40 authority used by startup absence proof.
    ///
    /// This sealed crate-local check prevents a generic protected authority for
    /// another namespace from authenticating shaped `AOSMSA02` bytes. Both the
    /// dedicated namespace scope and the purpose-scoped composite Mount source
    /// authority are accepted; the snapshot must still name this exact journal
    /// instance, scope, namespace, and sequence.
    pub(crate) fn validate_mount_source_inventory_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_mount_source_acquisition_snapshot(snapshot)
    }

    /// Validates a namespace-40 snapshot's immutable journal provenance.
    ///
    /// Unlike an effect snapshot, this accepts a later sequence in the same
    /// uncompacted journal. The inventory capability separately compares its
    /// exact acquisition row, allowing a canonical proof batch to be consumed
    /// across unrelated row commits without surviving compaction or target-row
    /// replacement.
    pub(crate) fn validate_mount_source_inventory_origin(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        if !Arc::ptr_eq(&self.journal.authority_instance, &snapshot.instance)
            || snapshot.namespace != self.namespace
            || snapshot.scope != self.scope
            || snapshot.sequence > self.journal.snapshot_sequence()
        {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::StaleAuthoritySnapshot,
            ));
        }
        Ok(())
    }

    /// Returns the current authority value for a logical key.
    ///
    /// The returned value borrows this guard, so it cannot remain live across a
    /// commit or another mutable authority operation.
    ///
    /// # Errors
    ///
    /// Returns `CanonicalJournalMechanicalErrorV1::Poisoned` after an ambiguous durable mutation,
    /// or `CanonicalJournalMechanicalErrorV1::ProtectedBoundary` if retained protected-open
    /// provenance is absent.
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.validate_generic_authority_read()?;
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
    /// Returns `CanonicalJournalMechanicalErrorV1::Poisoned` after an ambiguous durable mutation,
    /// or `CanonicalJournalMechanicalErrorV1::ProtectedBoundary` if retained protected-open
    /// provenance is absent.
    pub fn records(&self) -> Result<impl Iterator<Item = (&[u8], &[u8])>, JournalError> {
        self.validate_generic_authority_read()?;
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
    /// Returns `CanonicalJournalMechanicalErrorV1::Poisoned` after an ambiguous durable mutation,
    /// or `CanonicalJournalMechanicalErrorV1::ProtectedBoundary` if retained protected-open
    /// provenance is absent.
    pub fn is_materialized_empty(&self) -> Result<bool, JournalError> {
        self.validate_generic_authority_read()?;
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
    /// Returns `CanonicalJournalMechanicalErrorV1::Poisoned` after an ambiguous durable mutation,
    /// or `CanonicalJournalMechanicalErrorV1::ProtectedBoundary` if retained protected-open
    /// provenance is absent.
    pub fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.validate_generic_authority_read()?;
        self.journal.ensure_protected_authority()?;
        Ok(self.current_snapshot())
    }

    /// Rechecks this exact instance, purpose and current cut before an effect.
    ///
    /// # Errors
    /// Refuses a foreign purpose, changed sequence, lost custody or poison.
    pub fn validate_snapshot_for_effect(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_generic_authority_read()?;
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
    /// Returns `CanonicalJournalMechanicalErrorV1::Poisoned` after an ambiguous durable mutation,
    /// `CanonicalJournalMechanicalErrorV1::ProtectedBoundary` when this journal lacks retained
    /// protected-open provenance,
    /// `CanonicalJournalMechanicalErrorV1::ForeignAuthorityNamespace` when any supplied
    /// transaction record belongs to another namespace, or
    /// `CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot` when `preflight` belongs to
    /// another journal or namespace or its sequence is no longer current.
    /// Returns
    /// `CanonicalJournalMechanicalErrorV1::AuthorityPreflightMismatch` when `transactions` differ
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
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::AuthorityPreflightMismatch,
            ));
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

    pub(super) fn current_snapshot(&self) -> ProtectedJournalSnapshot {
        ProtectedJournalSnapshot {
            instance: Arc::clone(&self.journal.authority_instance),
            namespace: self.namespace,
            sequence: self.journal.snapshot_sequence(),
            scope: self.scope,
        }
    }

    pub(super) fn validate_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        if !Arc::ptr_eq(&self.journal.authority_instance, &snapshot.instance)
            || snapshot.namespace != self.namespace
            || snapshot.sequence != self.journal.snapshot_sequence()
            || snapshot.scope != self.scope
        {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::StaleAuthoritySnapshot,
            ));
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
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::ForeignAuthorityNamespace,
            ));
        }

        Ok(())
    }

    fn validate_generic_authority_read(&self) -> Result<(), JournalError> {
        if self.namespace == RecordNamespace::MountManagerStartupAuthority
            || self.scope == ProtectedAuthorityScope::MountManagerStartup
        {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::ForeignAuthorityNamespace,
            ));
        }
        Ok(())
    }

    fn validate_generic_authority_mutation(&self) -> Result<(), JournalError> {
        self.validate_generic_authority_read()?;
        if !matches!(
            self.scope,
            ProtectedAuthorityScope::SingleNamespace
                | ProtectedAuthorityScope::FixedMountSourceAcquisition
        ) {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::ForeignAuthorityNamespace,
            ));
        }
        Ok(())
    }

    /// Forecasts exact owner-only transactions without admitting an effect.
    ///
    /// # Errors
    /// Refuses a wrong purpose, malformed transaction or unavailable capacity.
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
}
