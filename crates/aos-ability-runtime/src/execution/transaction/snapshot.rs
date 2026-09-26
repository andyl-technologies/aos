//! Read-only validation and summaries for a durable execution journal.

use super::*;

impl CheckedExecutionJournalSnapshot {
    /// Reads a journal without mutation and checks its complete durable prefix.
    ///
    /// The existing journal is opened read-only under a nonblocking shared
    /// lock. The first record supplies the transaction and retained plan-bundle
    /// commitment; both are then held exact while every record is replayed
    /// against `plan`.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal is absent, insecure, locked, corrupt,
    /// empty, incompatible with the plan, or violates the execution state
    /// machine. An incomplete final frame is reported by the returned snapshot
    /// and remains untouched.
    pub fn read(
        plan: &CheckedEffectPlan,
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<Self, TransactionError> {
        let snapshot: JournalSnapshot<ExecutionEvent> =
            FileJournal::read_only_snapshot(path, limits)?;
        Self::from_snapshot(plan, snapshot)
    }

    /// Checks a journal opened through a descriptor-anchored parent boundary.
    ///
    /// `path` is used only for diagnostics. The descriptor is never written and
    /// remains under a nonblocking shared lock through the complete bounded read.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read`].
    pub fn read_file(
        plan: &CheckedEffectPlan,
        file: File,
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<Self, TransactionError> {
        let snapshot: JournalSnapshot<ExecutionEvent> =
            FileJournal::read_only_snapshot_file(file, path, limits)?;
        Self::from_snapshot(plan, snapshot)
    }

    fn from_snapshot(
        plan: &CheckedEffectPlan,
        snapshot: JournalSnapshot<ExecutionEvent>,
    ) -> Result<Self, TransactionError> {
        if !plan.is_executable() {
            return Err(TransactionError::PlanNotExecutable);
        }
        let first = snapshot
            .records()
            .first()
            .ok_or_else(|| invalid(1, "execution journal is empty"))?;
        let ExecutionEventKind::TransactionPlanned {
            transaction,
            plan_bundle,
            retained_roots: _,
            total_recovery_millis: _,
            ..
        } = first.body().body()
        else {
            return Err(invalid(1, "first record is not the transaction plan root"));
        };

        let expected_budget = aggregate_recovery_budget(plan)?;
        let expected_roots = retained_roots(&required_runtime_artifacts(plan));
        let mut replay = ReplayState::new(
            plan,
            transaction.clone(),
            *plan_bundle,
            expected_roots,
            expected_budget,
        );
        for record in snapshot.records() {
            replay.apply(plan, record.sequence(), record.body().body())?;
        }
        let verified_bytes = snapshot.verified_bytes();
        let incomplete_tail_bytes = snapshot.incomplete_tail_bytes();
        let operations = replay
            .operations
            .values()
            .map(|history| OperationSummary {
                operation: history.operation_id().clone(),
                status: if replay.skipped.contains(&history.operation_id().operation) {
                    OperationStatus::Skipped
                } else {
                    operation_status(history)
                },
                attempt: history.current_attempt(),
                elapsed_millis: history.elapsed_millis(),
                retained_resources: retained_resource_outputs(plan, history),
            })
            .collect::<Vec<_>>();
        let terminal = transaction_result(&operations);

        Ok(Self {
            transaction: transaction.clone(),
            plan_bundle: *plan_bundle,
            records: snapshot.into_records(),
            operations,
            verified_bytes,
            incomplete_tail_bytes,
            terminal,
        })
    }

    /// Returns the exact transaction identity rooted by the first record.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Returns the retained plan-bundle commitment rooted by the first record.
    #[must_use]
    pub const fn plan_bundle(&self) -> Sha256Digest {
        self.plan_bundle
    }

    /// Returns the complete event records after checked replay.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord<ExecutionEvent>] {
        &self.records
    }

    /// Returns operation outcomes derived from the checked durable prefix.
    #[must_use]
    pub fn operations(&self) -> &[OperationSummary] {
        &self.operations
    }

    /// Returns the digest committing the complete verified prefix.
    #[must_use]
    pub fn head_digest(&self) -> Sha256Digest {
        self.records.last().map_or_else(
            || Sha256Digest::from_bytes([0_u8; 32]),
            JournalRecord::digest,
        )
    }

    /// Returns the byte length of the complete verified prefix.
    #[must_use]
    pub const fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    /// Returns bytes belonging to an incomplete final frame.
    #[must_use]
    pub const fn incomplete_tail_bytes(&self) -> u64 {
        self.incomplete_tail_bytes
    }

    /// Returns the terminal result derived from the checked durable prefix.
    #[must_use]
    pub const fn terminal(&self) -> Option<TerminalResult> {
        self.terminal
    }
}
