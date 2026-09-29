//! Purpose-limited physical writer and opaque current-row readback for kind2.

use std::path::Path;

use aos_sandbox_protocol::mount_source_acquisition_state::{
    MountSourceAcquisitionStateV2, SourceProviderSessionV2,
};

use super::{Edge, OrdinaryCapacityRecordV4, graph, pending, prepare, rejoin, settlement};
use crate::journal::{
    CacheMutationGateV1, CommitResult, Journal, JournalError, JournalTransaction,
    ProtectedAuthorityScope, ProtectedJournalAuthority, ProtectedJournalSnapshot, RecordNamespace,
    RootSourceGenesisTransitionV1, SourceProjectAdmissionTransition, authority_preflight_digest,
    controller_source_genesis, source_tree_genesis,
};

/// Borrows the same fixed Mount physical writer for exact kind2 edges only.
///
/// Generic mutation is denied. Live Security admission and private Mount table
/// installation remain trusted higher-owner obligations, not lower proofs.
pub struct MountBarrierIdleReplacementJournalAuthorityV4<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

/// Retains one exact physical kind2 preflight; it proves no live Session custody.
#[must_use]
pub struct PreparedBarrierIdleReplacementV4 {
    transaction: JournalTransaction,
    floor: OrdinaryCapacityRecordV4,
    snapshot: ProtectedJournalSnapshot,
    transaction_digest: [u8; 32],
}

/// Proves exact installed physical rows at a held writer instance and sequence.
///
/// This does NOT prove Mount's private in-memory table installation. Any genuine
/// derivative holder can use it for the lower own DELETE; trusted Mount code
/// must install and compare its actual table first. No effect authority follows.
#[must_use]
pub struct Kind2ProtectedReadbackV4 {
    snapshot: ProtectedJournalSnapshot,
    floor: OrdinaryCapacityRecordV4,
}

impl<'journal> MountBarrierIdleReplacementJournalAuthorityV4<'journal> {
    pub(crate) fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        journal.ensure_protected_authority()?;
        let authority = ProtectedJournalAuthority {
            journal,
            namespace: RecordNamespace::MountSourceAcquisition,
            scope: ProtectedAuthorityScope::RootLocalRecoveryKind2,
        };
        authority.validate_root_local_startup_replay_v4()?;
        let writer = Self { authority };
        writer.require_current()?;
        Ok(writer)
    }

    fn require_current(&self) -> Result<(), JournalError> {
        self.authority.journal.ensure_protected_authority()?;
        self.authority.validate_held_root_owned_at(
            Path::new("/var/lib/aos/sandbox-mount"),
            "mount.journal",
        )?;
        if self.authority.scope != ProtectedAuthorityScope::RootLocalRecoveryKind2 {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Borrows namespace40 reads for the actual Security plan consumer.
    ///
    /// The raw guard cannot perform generic commits in this purpose scope.
    #[doc(hidden)]
    pub fn security_view(&self) -> &ProtectedJournalAuthority<'journal> {
        &self.authority
    }

    /// Returns the currently protected complete owner graph as nonauthorizing DATA.
    ///
    /// # Errors
    /// Refuses stale physical names, unhealthy writer, invalid graph or floors.
    pub fn current_source_state(&self) -> Result<MountSourceAcquisitionStateV2, JournalError> {
        self.require_current()?;
        Ok(graph(&self.authority.journal.state)?.legacy().clone())
    }

    /// Derives and preflights actual S/H plus its own exact local floor.
    ///
    /// The physical writer authorizes only this closed map. The trusted Security
    /// consumer must compare the successor to its real current plan and hold
    /// live custody through commit; these supplied Session bytes do not prove it.
    ///
    /// # Errors
    /// Refuses stale names, successor reuse, wrong owner edge, unproved native
    /// debt, overlapping local fences, malformed floors or insufficient headroom.
    pub fn prepare_barrier_idle_replacement(
        &self,
        successor: SourceProviderSessionV2,
    ) -> Result<PreparedBarrierIdleReplacementV4, JournalError> {
        self.require_current()?;
        let (transaction, floor) = prepare(&self.authority.journal.state, successor)?;
        self.preflight(&transaction, Edge::Admission)?;
        let transaction_digest = authority_preflight_digest(std::slice::from_ref(&transaction));
        Ok(PreparedBarrierIdleReplacementV4 {
            transaction,
            floor,
            snapshot: self.authority.snapshot()?,
            transaction_digest,
        })
    }

    /// Commits that exact current preflight and performs protected own readback.
    ///
    /// This checks physical currentness, not higher-owner live Session custody.
    ///
    /// # Errors
    /// Refuses stale sequence/instance/bytes or bounds; append/readback ambiguity
    /// poisons the writer and never returns a successful readback.
    pub fn commit_barrier_idle_replacement(
        &mut self,
        prepared: PreparedBarrierIdleReplacementV4,
    ) -> Result<Kind2ProtectedReadbackV4, JournalError> {
        self.require_current()?;
        self.authority
            .validate_mount_source_acquisition_snapshot(&prepared.snapshot)?;
        if authority_preflight_digest(std::slice::from_ref(&prepared.transaction))
            != prepared.transaction_digest
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.preflight(&prepared.transaction, Edge::Admission)?;
        self.append(&prepared.transaction, Edge::Admission)?;
        self.readback(prepared.floor)
            .inspect_err(|_| self.authority.journal.poisoned = true)
    }

    /// Rejoins every pending kind2 local floor under the current physical owner.
    ///
    /// Cold readback reconstructs no historical live Session or table installation.
    ///
    /// # Errors
    /// Refuses missing/changed postimages, dependency bindings or fixed names.
    pub fn pending_local_readbacks(&self) -> Result<Vec<Kind2ProtectedReadbackV4>, JournalError> {
        self.require_current()?;
        pending(&self.authority.journal.state)?
            .into_iter()
            .map(|floor| {
                Ok(Kind2ProtectedReadbackV4 {
                    snapshot: self.authority.snapshot()?,
                    floor,
                })
            })
            .collect()
    }

    fn readback(
        &self,
        floor: OrdinaryCapacityRecordV4,
    ) -> Result<Kind2ProtectedReadbackV4, JournalError> {
        self.require_current()?;
        let record = floor.to_journal_record();
        if self
            .authority
            .journal
            .get(RecordNamespace::GlobalCapacityReservation, record.key())
            != record.value()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        rejoin(&self.authority.journal.state, &floor)?;
        Ok(Kind2ProtectedReadbackV4 {
            snapshot: self.authority.snapshot()?,
            floor,
        })
    }

    /// Retires only this own floor after genuine current physical readback.
    ///
    /// Any derivative holder may invoke this lower method without Mount's private
    /// sequencing witness. Trusted Mount MUST install/compare its actual table
    /// first. This method proves no past in-memory installation or effect custody.
    ///
    /// # Errors
    /// Refuses stale evidence, wrong floor/rows/fences or accounting; ambiguous
    /// commit/final readback poisons the held writer and returns no effect permit.
    pub fn settle_kind2_local_readback(
        &mut self,
        readback: Kind2ProtectedReadbackV4,
    ) -> Result<CommitResult, JournalError> {
        self.require_current()?;
        self.authority
            .validate_mount_source_acquisition_snapshot(&readback.snapshot)?;
        rejoin(&self.authority.journal.state, &readback.floor)?;
        let transaction = settlement(&readback.floor)?;
        self.preflight(&transaction, Edge::InstalledDelete)?;
        let result = self.append(&transaction, Edge::InstalledDelete)?;
        let final_readback = (|| {
            self.require_current()?;
            graph(&self.authority.journal.state)?;
            if self
                .authority
                .journal
                .get(
                    RecordNamespace::GlobalCapacityReservation,
                    readback.floor.to_journal_record().key(),
                )
                .is_some()
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })();
        if let Err(error) = final_readback {
            self.authority.journal.poisoned = true;
            return Err(error);
        }
        Ok(result)
    }

    fn preflight(&self, transaction: &JournalTransaction, edge: Edge) -> Result<(), JournalError> {
        self.authority.journal.preflight_with_cache_gate(
            std::slice::from_ref(transaction),
            None,
            true,
            false,
            None,
            None,
            None,
            Some(edge),
            CacheMutationGateV1::Ordinary,
        )
    }

    fn append(
        &mut self,
        transaction: &JournalTransaction,
        edge: Edge,
    ) -> Result<CommitResult, JournalError> {
        self.require_current()?;
        self.authority.journal.commit_with_cache_gate(
            transaction,
            None,
            true,
            false,
            false,
            false,
            false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None,
            Some(edge),
            CacheMutationGateV1::Ordinary,
        )
    }
}
