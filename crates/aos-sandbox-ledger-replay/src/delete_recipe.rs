//! Shares the exact saved Delete COMMIT guards with private replay adapters.
//!
//! The recipe compares supplied historical maps and transactions only. Native
//! readback observers, descriptor ownership, effect gates and final crossings
//! stay with their real role owners. The preflight view binding borrows actual
//! supplied transactions and supplies no semantic success callback or authority.

/// Defines the existing pure Delete replay guards in a private adapter.
///
/// The invocation binds its actual mechanical error, borrowed preflight view,
/// existing canonical codec and transaction validator. It creates comparison
/// functions only; no writer, financial purpose or protected grant is emitted.
#[macro_export]
macro_rules! define_delete_replay_data_recipe_v1 {
    () => {
        pub(super) fn has_dependencies(state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>) -> bool {
            state.keys().any(|(namespace, key)| {
                *namespace == RecordNamespace::DesiredState && codec::reserved_key(key)
            })
        }

        pub(super) fn selected(transaction: &JournalTransaction) -> bool {
            transaction.records().iter().any(|record| {
                record.namespace() == RecordNamespace::DesiredState && codec::reserved_key(record.key())
            })
        }

        /// Checks selected payload headroom before the existing preview-map clone.
        pub(super) fn bound_preview(
            state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transactions: &[JournalTransaction],
            limits: JournalLimits,
        ) -> Result<(), JournalError> {
            bound_preview_view(
                state,
                &PreflightTransactionViewV1::Ordinary(transactions),
                limits,
            )
        }

        /// Borrows the current closed preflight view without copying any transaction.
        pub(super) fn bound_preview_view(
            state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transactions: &PreflightTransactionViewV1<'_>,
            limits: JournalLimits,
        ) -> Result<(), JournalError> {
            if !has_dependencies(state)
                && !(0..transactions.len()).any(|index| selected(transactions.transaction(index)))
            {
                return Ok(());
            }

            let current = state.iter().try_fold(0_usize, |total, ((_, key), value)| {
                total
                    .checked_add(key.len())
                    .and_then(|bytes| bytes.checked_add(value.len()))
                    .ok_or(JournalError::LimitExceeded("Delete preview payload"))
            })?;
            let additions = (0..transactions.len()).try_fold(0_usize, |total, index| {
                let transaction = transactions.transaction(index);
                transaction
                    .records()
                    .iter()
                    .try_fold(total, |total, record| {
                        total
                            .checked_add(record.key().len())
                            .and_then(|bytes| bytes.checked_add(record.value().map_or(0, <[u8]>::len)))
                            .ok_or(JournalError::LimitExceeded("Delete preview payload"))
                    })
            })?;
            let maximum = limits
                .maximum_materialized_bytes
                .checked_add(limits.maximum_transaction_bytes)
                .ok_or(JournalError::LimitExceeded("Delete preview payload"))?;
            if current > limits.maximum_materialized_bytes
                || current
                    .checked_add(additions)
                    .is_none_or(|bytes| bytes > maximum)
            {
                return Err(JournalError::LimitExceeded("Delete preview payload"));
            }
            // This bounds current payload plus proposed retained copies. It excludes
            // map nodes, decoded protobuf temporaries and allocator/kernel funding.
            Ok(())
        }

        /// Validates the same real predecessor for append, preview and cold COMMIT.
        pub(super) fn validate(
            state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transaction: &JournalTransaction,
            before_sequence: u64,
            limits: JournalLimits,
        ) -> Result<(), JournalError> {
            if !has_dependencies(state) && !selected(transaction) {
                return Ok(());
            }

            preserve_pending_members(state, transaction, before_sequence)?;
            if !selected(transaction) {
                return Ok(());
            }
            validate_transaction(transaction, limits)?;
            bound_preview(state, std::slice::from_ref(transaction), limits)?;

            let first = transaction.records().first().ok_or_else(invalid)?;
            if first.namespace() != RecordNamespace::DesiredState
                || !first.key().starts_with(codec::BATCH_PREFIX)
            {
                return Err(invalid());
            }
            let batch =
                DeleteBatchViewV1::decode(first.value().ok_or_else(invalid)?).map_err(|_| invalid())?;
            if first.key() != codec::batch_key(batch.project(), batch.operation())
                || transaction.id() != &batch.transaction()
                || batch.before_sequence() != before_sequence
                || state.contains_key(&(RecordNamespace::DesiredState, first.key().to_vec()))
            {
                return Err(invalid());
            }

            #[cfg(target_os = "linux")]
            validate_admission(state, transaction, batch)?;
            #[cfg(not(target_os = "linux"))]
            return Err(JournalError::UnsupportedProtectedOpen);
            Ok(())
        }

        /// Preserves old Live preimages and every immutable pending dependency.
        fn preserve_pending_members(
            state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transaction: &JournalTransaction,
            before_sequence: u64,
        ) -> Result<(), JournalError> {
            for ((namespace, key), value) in state {
                if *namespace != RecordNamespace::DesiredState {
                    continue;
                }
                if key.starts_with(codec::BATCH_PREFIX) {
                    let batch = DeleteBatchViewV1::decode(value).map_err(|_| invalid())?;
                    if key != &codec::batch_key(batch.project(), batch.operation()) {
                        return Err(invalid());
                    }
                    for descriptor in batch.companions_v2() {
                        let original = descriptor.map_err(|_| invalid())?.original_v1();
                        use aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRowKindV1 as Kind;
                        if transaction.records().iter().any(|record|
                            record.namespace() == RecordNamespace::DesiredState
                                && [Kind::Parent, Kind::Assignment, Kind::Reservation]
                                    .iter().any(|kind| record.key() == original.key_v1(*kind)))
                        {
                            return Err(JournalError::ProtectedBoundary);
                        }
                    }
                    reject_new_projection_dependencies_v2(state, transaction, batch)?;
                    let terminal = transaction.records().iter().any(|record|
                        record.namespace() == RecordNamespace::Operation
                            && record.key() == batch.operation().as_bytes());
                    if terminal {
                        // This recognizes DATA only. The live native writer
                        // separately requires its actual sealed completion loan.
                        aos_sandbox_protocol::domain_ledger::delete_root::controller_completion::
                            require_delete_terminal_controller_transition_data_v4(
                                state, transaction, batch, before_sequence,
                            ).map_err(|_| JournalError::ProtectedBoundary)?;
                    }
                    if transaction.records().iter().any(|record| {
                        (!terminal && record.namespace() == RecordNamespace::Operation
                            && record.key() == batch.operation().as_bytes())
                            || (record.namespace() == RecordNamespace::DesiredState
                                && (record.key() == key
                                    || !terminal && batch
                                        .rows(0)
                                        .any(|row| record.key() == codec::row_key(row, 0))))
                    }) {
                        return Err(JournalError::ProtectedBoundary);
                    }
                } else if key.starts_with(codec::TOMBSTONE_PREFIX) || key.starts_with(codec::HANDOFF_PREFIX)
                {
                    if transaction
                        .records()
                        .iter()
                        .any(|record| record.namespace() == *namespace && record.key() == key)
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
            }
            Ok(())
        }

        // A protected tombstone freezes its dependency frontier too. Merely
        // protecting old projection keys permits a newly keyed child or
        // attachment to acquire a reference to a resource already deleting.
        // This uses the same typed extractor as the real dependency planner;
        // no payload substring, descriptor hash or supplied boolean is proof.
        fn reject_new_projection_dependencies_v2(
            state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transaction: &JournalTransaction,
            batch: DeleteBatchViewV1<'_>,
        ) -> Result<(), JournalError> {
            use aos_sandbox_protocol::public_api::projection::{
                PROJECTION_KEY_PREFIX, decode_checked_public_projection_v1,
                dependencies::projection_dependencies_data_v2,
            };

            for proposed in transaction.records() {
                if proposed.namespace() != RecordNamespace::DesiredState
                    || !proposed.key().starts_with(PROJECTION_KEY_PREFIX)
                {
                    continue;
                }
                let Some(value) = proposed.value() else { continue; };
                let record = decode_checked_public_projection_v1(proposed.key(), value)
                    .map_err(|_| invalid())?;
                let dependencies = projection_dependencies_data_v2(&record)
                    .map_err(|_| invalid())?;
                for edge in dependencies.edges_v2() {
                    if batch.rows(0).any(|written|
                        written[0] == edge.dependency().code()
                            && &written[1..17] == edge.dependency().as_bytes())
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
                if matches!(record.resource(), aos_sandbox_protocol::public_api::projection::PublicProjectionResourceV1::Execution(_)) {
                    // A fresh execution in another Sandbox can consume an
                    // Attachment of the deleting live export. Compare the
                    // same full C assignment relation used by the planner.
                    for attachment in aos_sandbox_protocol::public_api::projection::iter_public_projection_rows_data_v2(
                        state.iter().filter(|((namespace, _), _)| *namespace == RecordNamespace::DesiredState)
                            .map(|((_, key), value)| (key.as_slice(), value.as_slice())),
                        Some(aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1::Attachment),
                    ) {
                        let attachment = attachment.map_err(|_| invalid())?;
                        let edge = aos_sandbox_protocol::public_api::projection::dependencies::
                            assignment_attachment_consumer_data_v2(&record, &attachment).map_err(|_| invalid())?;
                        if edge.is_some_and(|edge| batch.rows(0).any(|written|
                            written[0] == edge.dependency().code()
                                && &written[1..17] == edge.dependency().as_bytes()))
                        { return Err(JournalError::ProtectedBoundary); }
                    }
                }
            }
            Ok(())
        }

        #[cfg(target_os = "linux")]
        fn validate_admission(
            state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transaction: &JournalTransaction,
            batch: DeleteBatchViewV1<'_>,
        ) -> Result<(), JournalError> {
            let records = transaction.records();
            let local_start: usize = if records
                .get(4)
                .is_some_and(|record| record.namespace() == RecordNamespace::OwnershipGate)
            {
                5
            } else {
                4
            };
            let effects_start = local_start
                .checked_add(batch.count(0))
                .and_then(|offset| offset.checked_add(batch.count(2)))
                .and_then(|offset| offset.checked_add(1))
                .ok_or_else(invalid)?;
            if effects_start >= records.len() {
                return Err(invalid());
            }

            // W compares the retained native projection, but PUTs only a pending
            // overlay. Its predecessor remains untouched for audit and readback.
            for row in batch.rows(0) {
                require_projection(state, batch, row)?;
            }
            for row in batch.rows(1) {
                let namespace = RecordNamespace::from_byte(row[17])?;
                let key = codec::row_key(row, 1);
                let actual = state.get(&(namespace, key.to_vec()));
                if actual.is_some() != (row[20] == 1)
                    || actual.is_some_and(|value| codec::native_value_digest(value) != row[24..56])
                {
                    return Err(conflict());
                }
            }

            let mut offset = local_start;
            for resource in batch.rows(4) {
                let row = batch
                    .rows(0)
                    .find(|row| &row[..17] == resource)
                    .ok_or_else(invalid)?;
                let value = codec::tombstone(batch, row);
                if codec::native_value_digest(&value) != row[68..100] {
                    return Err(invalid());
                }
                let key = codec::tombstone_key(batch.project(), resource);
                if state.contains_key(&(RecordNamespace::DesiredState, key.clone())) {
                    return Err(conflict());
                }
                require_put(records.get(offset), &key, &value)?;
                offset += 1;
            }
            for row in batch.rows(2) {
                let key = codec::row_key(row, 2);
                let before = codec::collection(batch.project(), row, false);
                if state
                    .get(&(RecordNamespace::DesiredState, key.to_vec()))
                    .map(Vec::as_slice)
                    != Some(before.as_slice())
                {
                    return Err(conflict());
                }
                require_put(
                    records.get(offset),
                    key,
                    &codec::collection(batch.project(), row, true),
                )?;
                offset += 1;
            }
            let marker = records.get(offset).ok_or_else(invalid)?;
            if marker.namespace() != RecordNamespace::DesiredState
                || marker.key() != codec::handoff_key(batch.project(), batch.operation())
            {
                return Err(invalid());
            }
            codec::validate_handoff(marker.value().ok_or_else(invalid)?, batch).map_err(|_| invalid())?;
            if state.contains_key(&(RecordNamespace::DesiredState, marker.key().to_vec())) {
                return Err(conflict());
            }

            validate_delete_batch_admission_records_v1(batch, transaction, local_start, effects_start)
                .map_err(|_| JournalError::MalformedTransaction("invalid Delete batch admission metadata"))
        }

        #[cfg(target_os = "linux")]
        fn require_projection(
            state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            batch: DeleteBatchViewV1<'_>,
            row: &[u8],
        ) -> Result<(), JournalError> {
            use aos_sandbox_protocol::public_api::projection::{
                PublicProjectionKindV1 as Kind, PublicProjectionRecordV1,
                PublicProjectionResourceV1 as Resource, projection_key,
            };
            if row[0] == 9 {
                let (descriptor, _) = batch.companion_for_resource_v2(&row[..17])
                    .ok_or_else(invalid)?;
                return descriptor.require_original_state_v2(state).map_err(|_| conflict());
            }
            let kind = match row[0] {
                1 => Kind::Sandbox,
                2 => Kind::Execution,
                3 => Kind::Snapshot,
                4 => Kind::FilesystemView,
                5 => Kind::Attachment,
                _ => return Err(invalid()),
            };
            let identity: [u8; 16] = row[1..17].try_into().map_err(|_| invalid())?;
            let key = codec::row_key(row, 0);
            if key != projection_key(kind, identity) {
                return Err(invalid());
            }
            let value = state
                .get(&(RecordNamespace::DesiredState, key.to_vec()))
                .ok_or_else(conflict)?;
            if codec::native_value_digest(value) != row[28..60] {
                return Err(conflict());
            }
            let projection = PublicProjectionRecordV1::from_retained_record_bytes(kind, identity, value)
                .map_err(|_| invalid())?;
            let generation = match projection.resource() {
                Resource::Sandbox(value) => value.desired.as_option().map(|desired| desired.generation),
                Resource::Execution(value) => Some(value.desired_generation),
                Resource::FilesystemView(value) => Some(value.desired_generation),
                Resource::Attachment(value) => Some(value.desired_generation),
                Resource::Snapshot(value) => Some(value.desired_generation),
                _ => None,
            };
            if projection.project() != batch.project() || generation != Some(codec::raw64(&row[20..28])) {
                return Err(conflict());
            }
            Ok(())
        }

        fn require_put(
            record: Option<&JournalRecord>,
            key: &[u8],
            value: &[u8],
        ) -> Result<(), JournalError> {
            let record = record.ok_or_else(invalid)?;
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != key
                || record.value() != Some(value)
            {
                return Err(invalid());
            }
            Ok(())
        }

        fn invalid() -> JournalError {
            JournalError::MalformedRecord("invalid Delete batch native recipe")
        }

        fn conflict() -> JournalError {
            JournalError::MalformedTransaction("stale Delete batch member or collection")
        }
    };
}
