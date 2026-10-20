//! Shares the existing semantic replay sequence around actual native stages.
//!
//! The compile-time recipe keeps each actual consumer's native challenge
//! method and original error types at their existing frontier. It supplies no
//! callback, owner, authority constructor, payer or semantic completion port.
//! Source/Root/capacity historical predicates remain the canonical DATA graph;
//! the invoking private module supplies its already-owned native stage types.

/// Defines the sole semantic replay DATA sequence in a private native adapter.
///
/// This recipe preserves the original `SemanticCommitDataV1` and borrowed
/// scratch layout. Its methods return comparison decisions only. Native
/// challenge currentness remains the exact existing private method call at the
/// same point between Source family validation and later Root/capacity checks.
/// It neither constructs a challenge view nor accepts a completion callback.
///
/// The invocation module binds its existing errors, Source replay scratch,
/// canonical family modules and capacity comparison function. Both actual
/// consumers own these bindings privately; no public trait implementation can
/// supply a successful protected role or alter its native admission.
#[macro_export]
macro_rules! define_semantic_replay_data_recipe_v1 {
    () => {
        pub(super) fn validate_replayed_source_transaction(
            state: &source_tree_successor::State,
            transaction: &JournalTransaction,
            limits: JournalLimits,
            retaining: bool,
            original: &mut Option<Box<source_tree_successor::SourceReplayTransactionOriginalsV1>>,
        ) -> Result<bool, JournalError> {
            if !retaining {
                return source_tree_successor::validate_replayed_transaction(state, transaction, limits);
            }
            if original.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            // The role's complete semantic invoice precedes this hook. Keep
            // the same diagnostic graph without embedding its dormant plane
            // in every unrelated captured Session opening.
            *original = Some(Box::new(source_tree_successor::SourceReplayTransactionOriginalsV1::new()));
            let result = original
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_once(state, transaction, limits)?;
            Ok(result)
        }

        pub(super) fn validate_replayed_source_state(
            state: &source_tree_successor::State,
            compacted: bool,
            retaining: bool,
            original: &mut Option<Box<source_tree_successor::SourceReplayFamilyOriginalsV1>>,
        ) -> Result<(), JournalError> {
            if !retaining {
                return source_tree_successor::validate_replayed_state(state, compacted);
            }
            if original.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            *original = Some(Box::new(source_tree_successor::SourceReplayFamilyOriginalsV1::new()));
            source_tree_successor::validate_replayed_state_with_originals(
                state,
                compacted,
                original.as_deref_mut(),
            )?;
            drop(original.take());
            Ok(())
        }

        /// Copies semantic routing decisions after the actual preceding checks.
        #[derive(Clone, Copy)]
        pub(super) struct SemanticCommitDataV1 {
            pub(super) query_edge: Option<RootOwnerEdge>,
            pub(super) logical_replay: bool,
            pub(super) first_successor_replay: bool,
        }

        impl SemanticCommitDataV1 {
            pub(super) const fn compaction() -> Self {
                Self {
                    query_edge: None,
                    logical_replay: false,
                    first_successor_replay: false,
                }
            }
        }

        /// Borrows the actual caller-owned semantic prefixes without copying them.
        pub(super) struct SemanticReplayBorrowV1<'state> {
            pub(super) source_challenge_history:
                &'state mut Vec<source_original_native::SourceOriginalChallengeCheckpointV5>,
            pub(super) source_challenge_history_bytes: &'state mut u64,
            pub(super) source_original_replay:
                &'state mut source_original_native::replay::SourceOriginalReplayCacheV5,
            pub(super) source_history_compacted: &'state mut bool,
            pub(super) materialized_compaction: &'state mut bool,
            pub(super) source_family:
                &'state mut Option<Box<source_tree_successor::SourceReplayFamilyOriginalsV1>>,
            pub(super) source_transition:
                &'state mut Option<Box<source_tree_successor::SourceReplayTransactionOriginalsV1>>,
            pub(super) prospective: &'state mut Option<BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>>,
        }

        impl SemanticReplayBorrowV1<'_> {
            pub(super) fn observe_compaction(
                &mut self,
                state: &source_tree_successor::State,
                transaction: &JournalTransaction,
            ) {
                *self.materialized_compaction = true;
                *self.source_history_compacted = true;
                self.source_original_replay
                    .observe_compaction(&root_original_inventory::materialize(state, transaction));
            }

            pub(super) fn before_logical(
                &mut self,
                state: &source_tree_successor::State,
                transaction: &JournalTransaction,
                limits: JournalLimits,
                retain_source_family: bool,
                challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
                coordinates: NativeReplayCoordinates,
                begin_sequence: u64,
                commit_sequence: u64,
                begin_offset: u64,
                materialized_bytes: usize,
                source_journal_identity: FileIdentity,
            ) -> Result<SemanticCommitDataV1, JournalError> {
                aos_sandbox_protocol::domain_ledger::resource_bank::validate_recipient_transaction_v1(state, transaction)?;
                if !*self.materialized_compaction {
                    aos_sandbox_protocol::domain_ledger::resource_bank::validate_recovered_funding_transaction_v2(
                        state, transaction, begin_sequence, begin_offset)?;
                }
                let mut query_edge = None;
                if *self.materialized_compaction {
                    validate_replayed_source_state(&state, true, retain_source_family, self.source_family)?;
                    root_local_recovery::pending(&state)?;
                    root_original_native::pending(&state, limits)?;
                    root_original_inventory::validate_rejoined_capacity(
                        &state,
                        materialized_bytes,
                        coordinates.durable_end,
                        coordinates.committed_transactions,
                        limits,
                        coordinates.durable_next_sequence,
                    )?;
                    *self.materialized_compaction = false;
                }
                let first_successor_replay = validate_replayed_source_transaction(
                    &state,
                    transaction,
                    limits,
                    retain_source_family,
                    self.source_transition,
                )?;
                let source_edge = self.source_original_replay.replay_transaction(
                    &state,
                    transaction,
                    challenges,
                    limits,
                    begin_sequence,
                    commit_sequence,
                    begin_offset,
                    coordinates.offset,
                    coordinates
                        .committed_transactions
                        .checked_add(1)
                        .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
                    source_journal_identity.physical_pair(),
                )?;
                if !source_edge {
                    query_edge = root_original_inventory::replay_edge(&state, transaction, limits)?;
                    if query_edge.is_none()
                        && !root_original_native::validate_replayed_transaction(
                            &state,
                            transaction,
                            limits,
                            coordinates.expected_sequence,
                        )?
                    {
                        root_local_recovery::validate_replayed_transaction(&state, transaction)?;
                    }
                    if query_edge.is_none() {
                        root_original_inventory::preserve_other_owner(&state, transaction, limits)?;
                    }
                }
                source_original_native::challenge::capture_checkpoint(
                    self.source_challenge_history,
                    self.source_challenge_history_bytes,
                    transaction,
                    begin_sequence,
                    commit_sequence,
                    begin_offset,
                    coordinates.offset,
                    limits,
                )?;
                Ok(SemanticCommitDataV1 {
                    query_edge,
                    logical_replay: true,
                    first_successor_replay,
                })
            }

            pub(super) fn after_materialization(
                &mut self,
                state: &source_tree_successor::State,
                transaction: &JournalTransaction,
                limits: JournalLimits,
                coordinates: NativeReplayCoordinates,
                materialized_bytes: usize,
                decision: SemanticCommitDataV1,
            ) -> Result<(), JournalError> {
                if decision.logical_replay
                    && (decision.query_edge.is_some()
                        || decision.first_successor_replay
                        || root_original_inventory::has_query_floor(state)?
                        || root_original_inventory::has_query_floor_after(state, transaction)?)
                {
                    *self.prospective = Some(root_original_inventory::materialize(state, transaction));
                    let prospective = self
                        .prospective
                        .as_ref()
                        .ok_or(JournalError::ProtectedBoundary)?;
                    // Exact owner/settlement validation already ran above.
                    // Empty-change accounting charges that exact post-state;
                    // no new settlement interpretation or authority follows.
                    validate_reserved_capacity(
                        &prospective,
                        materialized_bytes,
                        &[],
                        None,
                        coordinates.offset,
                        coordinates
                            .committed_transactions
                            .checked_add(1)
                            .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
                        limits,
                        None,
                    )?;
                    root_original_inventory::require_sequence_headroom(
                        &prospective,
                        coordinates.expected_sequence,
                    )?;
                    if decision.first_successor_replay {
                        source_tree_successor::require_sequence_headroom(
                            &prospective,
                            coordinates.expected_sequence,
                        )?;
                    }
                    *self.prospective = None;
                }
                Ok(())
            }

            pub(super) fn finish_commit(
                &mut self,
                state: &source_tree_successor::State,
                logical_replay: bool,
            ) -> Result<(), JournalError> {
                if let Some(original) = self.source_transition.as_ref() {
                    original.require_complete()?;
                }
                if logical_replay {
                    aos_sandbox_protocol::domain_ledger::resource_bank::validate(state)?;
                    // Admission writes all companions and their existing gate in one
                    // transaction. Check the actual applied map before disposing its
                    // COMMIT; a later transaction cannot repair an invalid prefix.
                    aos_sandbox_protocol::domain_ledger::provisioning_resources::validate_provisioning_resource_links_v1(state)?;
                }
                // The SAME native/index update and every semantic COMMIT check passed.
                // A failed transaction never reaches this pure positive disposal.
                drop(self.source_transition.take());
                Ok(())
            }

            pub(super) fn finish_prefix(
                &mut self,
                state: &source_tree_successor::State,
                limits: JournalLimits,
                coordinates: NativeReplayCoordinates,
                materialized_bytes: usize,
                retain_source_family: bool,
            ) -> Result<(), JournalError> {
                validate_replayed_source_state(
                    state,
                    *self.materialized_compaction,
                    retain_source_family,
                    self.source_family,
                )?;
                root_local_recovery::pending(state)?;
                root_original_native::pending(state, limits)?;
                root_original_inventory::validate_rejoined_capacity(
                    state,
                    materialized_bytes,
                    coordinates.durable_end,
                    coordinates.committed_transactions,
                    limits,
                    coordinates.durable_next_sequence,
                )?;
                // The same whole-bank fold checks latest recipient precharges
                // after both ordinary replay and checkpoint reconstruction.
                aos_sandbox_protocol::domain_ledger::resource_bank::validate(state)?;
                // Compaction may split one valid snapshot over several native
                // transactions. Its complete companion/gate check belongs here.
                aos_sandbox_protocol::domain_ledger::provisioning_resources::validate_provisioning_resource_links_v1(state)?;
                Ok(())
            }
        }
    };
    (retained) => {
        /// Seals upper semantic orchestration to actual crate-known native adapters.
        ///
        /// This trait carries no account, File, native tuple or success callback. Its
        /// implementations forward existing closed parser/index stages only.
        pub(crate) trait SelectedReplayNativeV1 {
            type Error: std::error::Error + 'static;

            fn advance_once(&mut self) -> Result<bool, Self::Error>;

            // Comparison-only adapters owe no financial debit. Actual Source
            // and F role adapters override these private fixed-stage hooks and
            // retain their whole same-original debit before model allocation.
            fn prepare_semantic_commit_once(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn prepare_semantic_prefix_once(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            // The ordinary Domain adapter dispatches only its existing finite
            // history enum here. Selected adapters keep the original no-op.
            fn observe_history_commit_once(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }

            fn current_commit(
                &self,
            ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>>;
            fn validate_compaction_once(&mut self) -> Result<(), Self::Error>;
            fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error>;
            fn prepare_change_once(&mut self) -> Result<(), Self::Error>;
            fn apply_next_record_once(&mut self) -> Result<bool, Self::Error>;
            fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error>;
            fn finish_commit_once(&mut self) -> Result<(), Self::Error>;
            fn completed_prefix(
                &self,
            ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>>;
            fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error>;
        }

        impl SelectedReplayNativeV1
            for aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayV1<
                '_,
                '_,
            >
        {
            type Error = aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1;

            fn advance_once(&mut self) -> Result<bool, Self::Error> {
                self.advance_once()
            }

            fn current_commit(
                &self,
            ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>> {
                self.current_commit()
            }

            fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
                self.validate_compaction_once()
            }

            fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
                self.register_and_compare_index_once()
            }

            fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
                self.prepare_change_once()
            }

            fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
                self.apply_next_record_once()
            }

            fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
                self.finish_commit_accounting_once()
            }

            fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
                self.finish_commit_once()
            }

            fn completed_prefix(
                &self,
            ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>> {
                self.completed_prefix()
            }

            fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
                if self.completed_prefix().is_none() || self.failure().is_some() {
                    Err(aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1::Closed)
                } else {
                    Ok(())
                }
            }
        }

        /// Moves only the original semantic remainder beside its same native writer.
        pub(crate) struct SelectedSemanticRemainderDataV1 {
            pub(crate) source_challenge_history:
                Vec<source_original_native::SourceOriginalChallengeCheckpointV5>,
            pub(crate) source_original_replay: source_original_native::replay::SourceOriginalReplayCacheV5,
            pub(crate) source_history_compacted: bool,
            pub(crate) q04_lower_history_present: bool,
        }

        /// Keeps every reached upper semantic destination until its enclosing posts.
        pub(crate) struct SelectedSemanticReplayOriginalV1<E: std::error::Error + 'static> {
            source_challenge_history: Vec<source_original_native::SourceOriginalChallengeCheckpointV5>,
            source_challenge_history_bytes: u64,
            source_original_replay: source_original_native::replay::SourceOriginalReplayCacheV5,
            source_history_compacted: bool,
            materialized_compaction: bool,
            source_family: Option<Box<source_tree_successor::SourceReplayFamilyOriginalsV1>>,
            source_transition: Option<Box<source_tree_successor::SourceReplayTransactionOriginalsV1>>,
            prospective: Option<BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>>,
            q04_lower_history_present: bool,
            identity: Option<Result<FileIdentity, E>>,
            native: Option<Result<(), E>>,
            decision: Option<SemanticCommitDataV1>,
            outcome: Option<Result<(), JournalError>>,
            entered: bool,
            taken: bool,
        }

        impl<E: std::error::Error + 'static> SelectedSemanticReplayOriginalV1<E> {
            pub(crate) fn new() -> Self {
                Self {
                    source_challenge_history: Vec::new(),
                    source_challenge_history_bytes: 0,
                    source_original_replay: Default::default(),
                    source_history_compacted: false,
                    materialized_compaction: false,
                    source_family: None,
                    source_transition: None,
                    prospective: None,
                    q04_lower_history_present: false,
                    identity: None,
                    native: None,
                    decision: None,
                    outcome: None,
                    entered: false,
                    taken: false,
                }
            }

            fn semantic(&mut self) -> SemanticReplayBorrowV1<'_> {
                SemanticReplayBorrowV1 {
                    source_challenge_history: &mut self.source_challenge_history,
                    source_challenge_history_bytes: &mut self.source_challenge_history_bytes,
                    source_original_replay: &mut self.source_original_replay,
                    source_history_compacted: &mut self.source_history_compacted,
                    materialized_compaction: &mut self.materialized_compaction,
                    source_family: &mut self.source_family,
                    source_transition: &mut self.source_transition,
                    prospective: &mut self.prospective,
                }
            }

            // The returned C error is a stopping projection. The opening still holds
            // actual parser/index partials and the original source of that failure.
            fn native_step<T>(
                destination: &mut Option<Result<(), E>>,
                returned: Result<T, E>,
            ) -> Result<T, JournalError> {
                match returned {
                    Ok(value) => {
                        *destination = Some(Ok(()));
                        Ok(value)
                    }
                    Err(cause) => {
                        *destination = Some(Err(cause));
                        Err(JournalError::ProtectedBoundary)
                    }
                }
            }

            /// Drives the sole semantic engine against an actual sealed native cursor.
            pub(crate) fn observe_native_once<N: SelectedReplayNativeV1<Error = E>>(
                &mut self,
                cursor: &mut N,
                identity: FileIdentity,
                limits: JournalLimits,
            ) -> Result<(), ()> {
                self.observe_with_context_once(cursor, identity, limits, true, None)
            }

            /// Keeps ordinary challenge identity and immediate family disposal.
            pub(crate) fn observe_ordinary_once<N: SelectedReplayNativeV1<Error = E>>(
                &mut self,
                cursor: &mut N,
                identity: FileIdentity,
                limits: JournalLimits,
                challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
            ) -> Result<(), ()> {
                self.observe_with_context_once(cursor, identity, limits, false, challenges)
            }

            fn observe_with_context_once<N: SelectedReplayNativeV1<Error = E>>(
                &mut self,
                cursor: &mut N,
                identity: FileIdentity,
                limits: JournalLimits,
                retaining: bool,
                challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
            ) -> Result<(), ()> {
                if self.entered || self.outcome.is_some() {
                    return Err(());
                }
                self.entered = true;
                self.outcome = Some((|| {
                    loop {
                        let reached = Self::native_step(&mut self.native, cursor.advance_once())?;
                        if !reached {
                            break;
                        }
                        Self::native_step(
                            &mut self.native,
                            cursor.prepare_semantic_commit_once(),
                        )?;
                        {
                            let commit = cursor
                                .current_commit()
                                .ok_or(JournalError::ProtectedBoundary)?;
                            let (begin_sequence, _) = commit.begin_position();
                            delete_batch::validate(
                                commit.prior_state(),
                                commit.transaction(),
                                begin_sequence,
                                limits,
                            )?;
                        }
                        Self::native_step(&mut self.native, cursor.observe_history_commit_once())?;
                        let compacting = {
                            let commit = cursor
                                .current_commit()
                                .ok_or(JournalError::ProtectedBoundary)?;
                            let compacting = commit
                                .compaction_candidate_before_validation()
                                .ok_or(JournalError::ProtectedBoundary)?;
                            if compacting
                                && (delete_batch::has_dependencies(commit.prior_state())
                                    || delete_batch::selected(commit.transaction()))
                            {
                                return Err(JournalError::ProtectedBoundary);
                            }
                            compacting
                        };
                        Self::native_step(&mut self.native, cursor.validate_compaction_once())?;
                        {
                            let commit = cursor
                                .current_commit()
                                .ok_or(JournalError::ProtectedBoundary)?;
                            if compacting {
                                self.semantic()
                                    .observe_compaction(commit.prior_state(), commit.transaction());
                                self.decision = Some(SemanticCommitDataV1::compaction());
                            } else {
                                let (begin_sequence, begin_offset) = commit.begin_position();
                                self.decision = Some(self.semantic().before_logical(
                                    commit.prior_state(),
                                    commit.transaction(),
                                    limits,
                                    retaining,
                                    challenges,
                                    commit.coordinates(),
                                    begin_sequence,
                                    commit.commit_sequence(),
                                    begin_offset,
                                    commit.materialized_bytes(),
                                    identity,
                                )?);
                            }
                        }
                        Self::native_step(&mut self.native, cursor.register_and_compare_index_once())?;
                        Self::native_step(&mut self.native, cursor.prepare_change_once())?;
                        {
                            let commit = cursor
                                .current_commit()
                                .ok_or(JournalError::ProtectedBoundary)?;
                            let decision = self.decision.ok_or(JournalError::ProtectedBoundary)?;
                            self.semantic().after_materialization(
                                commit.prior_state(),
                                commit.transaction(),
                                limits,
                                commit.coordinates(),
                                commit.materialized_bytes(),
                                decision,
                            )?;
                        }
                        let record_count = cursor
                            .current_commit()
                            .ok_or(JournalError::ProtectedBoundary)?
                            .transaction()
                            .records()
                            .len();
                        for index in 0..record_count {
                            let commit = cursor
                                .current_commit()
                                .ok_or(JournalError::ProtectedBoundary)?;
                            let record = commit
                                .transaction()
                                .records()
                                .get(index)
                                .ok_or(JournalError::ProtectedBoundary)?;
                            // The original deny-only provenance bit advances BEFORE
                            // native/index application, including a later failed step.
                            self.q04_lower_history_present |= is_q04_lower_history_record_v1(record);
                            let applied =
                                Self::native_step(&mut self.native, cursor.apply_next_record_once())?;
                            if !applied {
                                return Err(JournalError::ProtectedBoundary);
                            }
                        }
                        Self::native_step(&mut self.native, cursor.finish_commit_accounting_once())?;
                        {
                            let commit = cursor
                                .current_commit()
                                .ok_or(JournalError::ProtectedBoundary)?;
                            let decision = self.decision.ok_or(JournalError::ProtectedBoundary)?;
                            self.semantic().finish_commit(commit.prior_state(), decision.logical_replay)?;
                        }
                        Self::native_step(&mut self.native, cursor.finish_commit_once())?;
                        self.decision = None;
                    }
                    Self::native_step(
                        &mut self.native,
                        cursor.prepare_semantic_prefix_once(),
                    )?;
                    let prefix = cursor
                        .completed_prefix()
                        .ok_or(JournalError::ProtectedBoundary)?;
                    self.semantic().finish_prefix(
                        prefix.state(),
                        limits,
                        prefix.coordinates(),
                        prefix.materialized_bytes(),
                        retaining,
                    )?;
                    // The role's actual invocation guard stays held through the sole
                    // semantic final-prefix checks, including a semantic Err at EOF.
                    Self::native_step(&mut self.native, cursor.finish_semantic_window_once())?;
                    Ok(())
                })());
                if matches!(self.outcome, Some(Ok(()))) {
                    Ok(())
                } else {
                    Err(())
                }
            }

            /// Prices only actual inline semantic construction/control planes.
            ///
            /// Source-family backing remains a distinct genuine caller payment
            /// before its Box; creating these empty controls allocates none.
            pub(crate) fn receiving_construction_bytes_v1() -> Option<usize> {
                std::mem::size_of::<Self>()
                    .checked_mul(2)?
                    .checked_add(std::mem::size_of::<SemanticReplayBorrowV1<'_>>().checked_mul(2)?)?
                    .checked_add(std::mem::size_of::<SelectedSemanticRemainderDataV1>().checked_mul(2)?)?
                    .checked_add(std::mem::size_of::<SemanticCommitDataV1>().checked_mul(2)?)
            }

            pub(crate) fn fixed_demand_v1() -> Result<aos_sandbox_model::ResourceVector, JournalError> {
                use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

                let invalid = || JournalError::LimitExceeded("Controller semantic replay geometry");
                let (family_bytes, _representation_controls) =
                    source_native_family_fixed_footprint_v1().ok_or_else(invalid)?;
                let bytes = Self::receiving_construction_bytes_v1()
                    .and_then(|bytes| bytes.checked_add(family_bytes))
                    .ok_or_else(invalid)?;
                Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?))
            }

            /// Moves the same completed semantic DATA only into the private Journal facade.
            pub(crate) fn take_remainder_once(&mut self) -> Option<SelectedSemanticRemainderDataV1> {
                if self.taken || !matches!(self.outcome, Some(Ok(()))) {
                    return None;
                }
                self.taken = true;
                Some(SelectedSemanticRemainderDataV1 {
                    source_challenge_history: std::mem::take(&mut self.source_challenge_history),
                    source_original_replay: std::mem::take(&mut self.source_original_replay),
                    source_history_compacted: self.source_history_compacted,
                    q04_lower_history_present: self.q04_lower_history_present,
                })
            }

            /// Borrows the original deep Source transition/family diagnostic.
            ///
            /// Existing caller failure selectors keep their own chronology.
            /// This supplies no replay completion, lender or authority and
            /// leaves the whole actual typed validator original resident.
            pub(crate) fn source_failure_cause_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.source_transition.as_deref().and_then(|original| original.cause())
                    .or_else(|| self.source_family.as_deref()
                        .and_then(|original| original.cause())
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
            }

            /// Drops only the actual prospective map before current native work.
            ///
            /// The ordinary frame-error arm formerly dropped this reached clone
            /// before its transaction/frame. Other semantic originals remain
            /// resident until their separate post-current disposal window.
            pub(crate) fn dispose_ordinary_prospective_v1(&mut self) {
                drop(self.prospective.take());
            }

            /// Moves actual ordinary errors after the caller's current-stage disposal.
            ///
            /// The caller first retires prospective work, then current parser
            /// work. Consuming this owner disposes the remaining actual upper
            /// semantic scratch, then pending parser/index/native originals in
            /// their existing order. Selected originals never use this entry.
            pub(crate) fn into_ordinary_errors(mut self) -> (Option<E>, Option<JournalError>) {
                let native = self.identity.take().and_then(Result::err)
                    .or_else(|| self.native.take().and_then(Result::err));
                let semantic = self.outcome.take().and_then(Result::err);
                // Explicit ordinary local order; retained/default field Drop
                // stays unchanged. False-retention has no family allocations.
                drop(self.source_transition.take());
                drop(self.source_family.take());
                drop(self.prospective.take());
                drop(std::mem::take(&mut self.source_original_replay));
                drop(std::mem::take(&mut self.source_challenge_history));
                drop(self);
                (native, semantic)
            }

            /// Reports a retained native stop without granting semantic success.
            ///
            /// The actual native capsule owns its deeper cause. This chooses that
            /// original before the upper loop's boundary marker when reporting failure.
            pub(crate) fn native_failure_is_selected_v1(&self) -> bool {
                matches!(self.native, Some(Err(_)))
            }

            pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.identity
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
                    .or_else(|| {
                        self.native
                            .as_ref()
                            .and_then(|result| result.as_ref().err())
                            .map(|cause| cause as _)
                    })
                    .or_else(|| {
                        self.outcome
                            .as_ref()
                            .and_then(|result| result.as_ref().err())
                            .map(|cause| cause as _)
                    })
            }
        }
    };
}


/// Recognizes the same deny-only Q04 lower-history key set as comparison DATA.
///
/// This selector never supplies a lower participant, currentness proof or
/// permission to clear history; actual role gates retain those obligations.
#[must_use]
pub fn is_q04_lower_history_record_data_v1(
    record: &aos_sandbox_protocol::domain_ledger::transaction::JournalRecord,
) -> bool {
    use aos_sandbox_model::RecordNamespace;

    (record.namespace() == RecordNamespace::SourceDomainPolicyHold
        && record.key() == b"\0aos-source-domain-q04-pending-v1\0")
        || (record.namespace() == RecordNamespace::DesiredState
            && record.key() == b"\0aos-cache-q04-pending-v1\0")
        || (record.namespace() == RecordNamespace::ControllerPolicyHold
            && record.key() == b"\0aos-controller-q04-cut-v1\0")
        || (record.namespace() == RecordNamespace::DesiredState
            && record.key().starts_with(b"\0aos-q04-root-"))
}
