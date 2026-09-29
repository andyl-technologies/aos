//! Named kind2/kind5 physical writers sharing one private append/readback core.

use std::path::Path;

use aos_sandbox_protocol::mount_source_acquisition_state::{
    DeadProviderExecutionProjectionV2, MountSourceAcquisitionStateV2, SourceProviderSessionV2,
};

use super::{
    Edge, Kind, OrdinaryCapacityRecordV4, dead_replacement, graph, pending, prepare, rejoin,
    settlement,
};
use crate::journal::{
    CacheMutationGateV1, CommitResult, Journal, JournalError, JournalTransaction,
    ProtectedAuthorityScope, ProtectedJournalAuthority, ProtectedJournalSnapshot, RecordNamespace,
    RootOwnerEdge, RootSourceGenesisTransitionV1, SourceProjectAdmissionTransition,
    authority_preflight_digest, controller_source_genesis, source_tree_genesis,
};

/// Borrows one of the two closed fixed Mount local physical scopes.
///
/// Generic mutation is denied. Live Security admission and private Mount table
/// installation remain trusted higher-owner obligations, not lower proofs.
struct LocalRecoveryWriter<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

/// Retains one exact physical local preflight, never live Session custody.
#[must_use]
struct PreparedLocalReplacement {
    transaction: JournalTransaction,
    floor: OrdinaryCapacityRecordV4,
    snapshot: ProtectedJournalSnapshot,
    transaction_digest: [u8; 32],
    edge: Edge,
}

/// Proves exact installed physical rows at a held writer instance and sequence.
///
/// This does NOT prove Mount's private in-memory table installation. Any genuine
/// derivative holder can use it for the lower own DELETE; trusted Mount code
/// must install and compare its actual table first. No effect authority follows.
#[must_use]
struct LocalReadback {
    snapshot: ProtectedJournalSnapshot,
    floor: OrdinaryCapacityRecordV4,
}

impl<'journal> LocalRecoveryWriter<'journal> {
    fn claim(
        journal: &'journal mut Journal,
        scope: ProtectedAuthorityScope,
    ) -> Result<Self, JournalError> {
        journal.ensure_protected_authority()?;
        let authority = ProtectedJournalAuthority {
            journal,
            namespace: RecordNamespace::MountSourceAcquisition,
            scope,
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
        if !matches!(
            self.authority.scope,
            ProtectedAuthorityScope::RootLocalRecoveryKind2
                | ProtectedAuthorityScope::RootLocalRecoveryKind5
        ) {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Borrows namespace40 reads for the actual Security plan consumer.
    ///
    /// The raw guard cannot perform generic commits in this purpose scope.
    #[doc(hidden)]
    fn security_view(&self) -> &ProtectedJournalAuthority<'journal> {
        &self.authority
    }

    /// Returns the currently protected complete owner graph as nonauthorizing DATA.
    ///
    /// # Errors
    /// Refuses stale physical names, unhealthy writer, invalid graph or floors.
    fn current_source_state(&self) -> Result<MountSourceAcquisitionStateV2, JournalError> {
        self.require_current()?;
        Ok(graph(&self.authority.journal.state)?.legacy().clone())
    }

    fn kind(&self) -> Kind {
        match self.authority.scope {
            ProtectedAuthorityScope::RootLocalRecoveryKind5 => Kind::DeadReplacement,
            _ => Kind::BarrierIdleReplacement,
        }
    }

    fn prepare_barrier_idle_replacement(
        &self,
        successor: SourceProviderSessionV2,
    ) -> Result<PreparedLocalReplacement, JournalError> {
        self.require_current()?;
        if self.kind() != Kind::BarrierIdleReplacement {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let (transaction, floor) = prepare(&self.authority.journal.state, successor)?;
        self.prepared(transaction, floor, Edge::Admission)
    }

    fn prepare_dead_replacement(
        &self,
        successor: SourceProviderSessionV2,
        death: DeadProviderExecutionProjectionV2,
    ) -> Result<PreparedLocalReplacement, JournalError> {
        self.require_current()?;
        if self.kind() != Kind::DeadReplacement {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let (transaction, floor) =
            dead_replacement::prepare(&self.authority.journal.state, successor, death)?;
        self.prepared(transaction, floor, Edge::DeadAdmission)
    }

    fn prepared(
        &self,
        transaction: JournalTransaction,
        floor: OrdinaryCapacityRecordV4,
        edge: Edge,
    ) -> Result<PreparedLocalReplacement, JournalError> {
        self.preflight(&transaction, edge)?;
        let transaction_digest = authority_preflight_digest(std::slice::from_ref(&transaction));
        Ok(PreparedLocalReplacement {
            transaction,
            floor,
            snapshot: self.authority.snapshot()?,
            transaction_digest,
            edge,
        })
    }

    /// Commits that exact current preflight and performs protected own readback.
    ///
    /// This checks physical currentness, not higher-owner live Session custody.
    ///
    /// # Errors
    /// Refuses stale sequence/instance/bytes or bounds; append/readback ambiguity
    /// poisons the writer and never returns a successful readback.
    fn commit_prepared(
        &mut self,
        prepared: PreparedLocalReplacement,
    ) -> Result<LocalReadback, JournalError> {
        self.require_current()?;
        self.authority
            .validate_mount_source_acquisition_snapshot(&prepared.snapshot)?;
        if authority_preflight_digest(std::slice::from_ref(&prepared.transaction))
            != prepared.transaction_digest
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.preflight(&prepared.transaction, prepared.edge)?;
        self.append(&prepared.transaction, prepared.edge)?;
        self.readback(prepared.floor)
            .inspect_err(|_| self.authority.journal.poisoned = true)
    }

    /// Rejoins this named scope's local floors under the current physical owner.
    ///
    /// Cold readback reconstructs no historical live Session or table installation.
    ///
    /// # Errors
    /// Refuses missing/changed postimages, dependency bindings or fixed names.
    fn pending_local_readbacks(&self) -> Result<Vec<LocalReadback>, JournalError> {
        self.require_current()?;
        pending(&self.authority.journal.state)?
            .into_iter()
            .filter(|floor| floor.data().kind == self.kind())
            .map(|floor| {
                Ok(LocalReadback {
                    snapshot: self.authority.snapshot()?,
                    floor,
                })
            })
            .collect()
    }

    fn readback(&self, floor: OrdinaryCapacityRecordV4) -> Result<LocalReadback, JournalError> {
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
        Ok(LocalReadback {
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
    fn settle_local_readback(
        &mut self,
        readback: LocalReadback,
    ) -> Result<CommitResult, JournalError> {
        self.require_current()?;
        self.authority
            .validate_mount_source_acquisition_snapshot(&readback.snapshot)?;
        if readback.floor.data().kind != self.kind() {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
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
            Some(RootOwnerEdge::Local(edge)),
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
            Some(RootOwnerEdge::Local(edge)),
            CacheMutationGateV1::Ordinary,
        )
    }
}

/// Borrows the same fixed Mount physical writer for exact kind2 edges only.
///
/// Generic mutation is denied. Security custody and trusted private Mount table
/// installation remain higher-owner obligations, not physical readback proofs.
pub struct MountBarrierIdleReplacementJournalAuthorityV4<'journal> {
    writer: LocalRecoveryWriter<'journal>,
}

/// Retains one exact kind2 preflight; it proves no live Session custody.
#[must_use]
pub struct PreparedBarrierIdleReplacementV4(PreparedLocalReplacement);

/// Proves exact kind2 physical rows, not trusted Mount table installation.
///
/// A genuine physical writer holder can call lower DELETE without installation;
/// the private Mount coordinator must install and compare first.
#[must_use]
pub struct Kind2ProtectedReadbackV4(LocalReadback);

impl<'journal> MountBarrierIdleReplacementJournalAuthorityV4<'journal> {
    pub(crate) fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        Ok(Self {
            writer: LocalRecoveryWriter::claim(
                journal,
                ProtectedAuthorityScope::RootLocalRecoveryKind2,
            )?,
        })
    }

    /// Borrows readonly namespace40 for the actual Security plan consumer.
    #[doc(hidden)]
    pub fn security_view(&self) -> &ProtectedJournalAuthority<'journal> {
        self.writer.security_view()
    }

    /// Returns complete current owner graph DATA under the held writer.
    ///
    /// # Errors
    /// Refuses stale physical names, unhealthy writer, invalid graph or floors.
    pub fn current_source_state(&self) -> Result<MountSourceAcquisitionStateV2, JournalError> {
        self.writer.current_source_state()
    }

    /// Preflights exact S/H plus its local floor, without proving live custody.
    ///
    /// # Errors
    /// Refuses wrong owner edges, overlapping fences, unproved native debt,
    /// stale physical currentness, malformed rows or insufficient headroom.
    pub fn prepare_barrier_idle_replacement(
        &self,
        successor: SourceProviderSessionV2,
    ) -> Result<PreparedBarrierIdleReplacementV4, JournalError> {
        Ok(PreparedBarrierIdleReplacementV4(
            self.writer.prepare_barrier_idle_replacement(successor)?,
        ))
    }

    /// Commits an exact current kind2 preflight and reads back its own floor.
    ///
    /// # Errors
    /// Refuses stale evidence or bounds; append/readback ambiguity poisons.
    pub fn commit_barrier_idle_replacement(
        &mut self,
        prepared: PreparedBarrierIdleReplacementV4,
    ) -> Result<Kind2ProtectedReadbackV4, JournalError> {
        Ok(Kind2ProtectedReadbackV4(
            self.writer.commit_prepared(prepared.0)?,
        ))
    }

    /// Rejoins only kind2 floors after validating all supported local families.
    ///
    /// # Errors
    /// Refuses changed graph, rows, fences or physical currentness.
    pub fn pending_local_readbacks(&self) -> Result<Vec<Kind2ProtectedReadbackV4>, JournalError> {
        Ok(self
            .writer
            .pending_local_readbacks()?
            .into_iter()
            .map(Kind2ProtectedReadbackV4)
            .collect())
    }

    /// Retires this own floor after current physical readback.
    ///
    /// This does not enforce trusted Mount's private installation sequence.
    ///
    /// # Errors
    /// Refuses stale/wrong readback or accounting; ambiguity poisons the writer.
    pub fn settle_kind2_local_readback(
        &mut self,
        readback: Kind2ProtectedReadbackV4,
    ) -> Result<CommitResult, JournalError> {
        self.writer.settle_local_readback(readback.0)
    }
}

/// Borrows the same fixed physical writer for exact kind5 DeadReplacement only.
///
/// Supplied canonical death/Session DATA is not Security custody or protected
/// execution-death evidence. Trusted Mount must consume the genuine current
/// death-bound plan and synchronize table plus cold indexes before own DELETE.
pub struct MountDeadReplacementJournalAuthorityV4<'journal> {
    writer: LocalRecoveryWriter<'journal>,
}

/// Retains one exact physical kind5 preflight, never execution-death authority.
#[must_use]
pub struct PreparedDeadReplacementV4(PreparedLocalReplacement);

/// Proves kind5 physical postimages, not Mount runtime-index installation.
///
/// A genuine derivative writer holder may call lower DELETE without the private
/// Mount coordinator. No live custody, descriptor, signing or send grant follows.
#[must_use]
pub struct Kind5ProtectedReadbackV4(LocalReadback);

impl<'journal> MountDeadReplacementJournalAuthorityV4<'journal> {
    pub(crate) fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        Ok(Self {
            writer: LocalRecoveryWriter::claim(
                journal,
                ProtectedAuthorityScope::RootLocalRecoveryKind5,
            )?,
        })
    }

    /// Borrows readonly namespace40 for the real death-bound plan consumer.
    #[doc(hidden)]
    pub fn security_view(&self) -> &ProtectedJournalAuthority<'journal> {
        self.writer.security_view()
    }

    /// Returns complete current owner graph DATA under the same held writer.
    ///
    /// # Errors
    /// Refuses stale names, unhealthy journal or invalid graph/floors.
    pub fn current_source_state(&self) -> Result<MountSourceAcquisitionStateV2, JournalError> {
        self.writer.current_source_state()
    }

    /// Derives and preflights exact T/S/[A]/H plus its kind5/profile1 floor.
    ///
    /// The closed physical route rederives the full proposal. Its DATA arguments
    /// do not prove live Security custody or protected execution death.
    ///
    /// # Errors
    /// Refuses wrong pending/first/repeated/death joins, stale names, existing
    /// local fences, unproved original native debt, malformed floors or limits.
    pub fn prepare_dead_replacement(
        &self,
        successor: SourceProviderSessionV2,
        death: DeadProviderExecutionProjectionV2,
    ) -> Result<PreparedDeadReplacementV4, JournalError> {
        Ok(PreparedDeadReplacementV4(
            self.writer.prepare_dead_replacement(successor, death)?,
        ))
    }

    /// Commits this exact current physical kind5 preflight and reads it back.
    ///
    /// # Errors
    /// Refuses stale evidence/limits; append or readback ambiguity poisons.
    pub fn commit_dead_replacement(
        &mut self,
        prepared: PreparedDeadReplacementV4,
    ) -> Result<Kind5ProtectedReadbackV4, JournalError> {
        Ok(Kind5ProtectedReadbackV4(
            self.writer.commit_prepared(prepared.0)?,
        ))
    }

    /// Rejoins only kind5 floors after canonical whole-family validation.
    ///
    /// # Errors
    /// Refuses missing/changed postimages, references, fences or current names.
    pub fn pending_local_readbacks(&self) -> Result<Vec<Kind5ProtectedReadbackV4>, JournalError> {
        Ok(self
            .writer
            .pending_local_readbacks()?
            .into_iter()
            .map(Kind5ProtectedReadbackV4)
            .collect())
    }

    /// Retires only this own kind5 floor after current physical readback.
    ///
    /// Trusted private Mount must first install/compare its five maps AND four
    /// cold indexes. This lower method cannot prove that in-memory sequencing,
    /// and every genuine derivative physical holder can invoke it without it.
    ///
    /// # Errors
    /// Refuses stale/wrong physical evidence, bindings or accounting; ambiguous
    /// append/final readback poisons and returns no effect authority.
    pub fn settle_kind5_local_readback(
        &mut self,
        readback: Kind5ProtectedReadbackV4,
    ) -> Result<CommitResult, JournalError> {
        self.writer.settle_local_readback(readback.0)
    }
}
