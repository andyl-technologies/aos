//! Shares the existing ordinary Git owner, Mount and Storage comparisons.
//!
//! Each concrete coordinator supplies its actual immutable native read view.
//! Private module aliases bind only the other canonical DATA recipes. They are
//! not request-provided callbacks, native owners, signers or append exceptions.
//! Currentness, financial admission and every final crossing stay at the actual
//! writer; these comparisons only preserve the old ordinary refusal boundary.

/// Defines the unchanged ordinary Git policy around actual held-path DATA.
#[macro_export]
macro_rules! define_provider_git_ordinary_data_recipe_v1 {
    () => {
        fn controller_fenced_read_v1<P>(
            read: aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, P>,
            state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        ) -> bool {
            *read.path() == std::path::Path::new("/var/lib/aos/sandboxd/controller.journal")
            && has_durable_owner_fence_v1(state)
        }

        pub(super) fn require_owner_transition_read_v1<P>(
            read: aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, P>,
            state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transaction: &JournalTransaction,
        ) -> Result<(), JournalError> {
            let fixed_remote_owner = matches!(read.path().to_str(),
                Some("/var/lib/aos/sandbox-mount/mount.journal")
                    | Some("/var/lib/aos/sandbox-storage/storage-state.journal")
                    | Some("/var/lib/aos/sandbox/policy-compiler/authority.journal")
                    | Some("/var/lib/aos/sandbox/policy-compiler/state.journal"));
            if fixed_remote_owner && has_durable_owner_fence_v1(state) {
                // These owners have no admitted successor mutation in the first
                // empty-cohort profile. Readback and original Broker-session
                // outcome journals are separate and retain their existing engine.
                return Err(JournalError::ProtectedBoundary);
            }
            if !controller_fenced_read_v1(read, state) {
                return Ok(());
            }

            if transaction.records().first().is_some_and(|record| {
                matches!(record.namespace(), RecordNamespace::CliAuthorizationTime
                    | RecordNamespace::PublisherAuthority)
            }) {
                provider_policy_data::require_complete_coverage_read_state_data_v1(state)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                return match transaction.records()[0].namespace() {
                    RecordNamespace::CliAuthorizationTime =>
                        provider_cli_floor_data::require_git_coverage_floor_from_state_v1(
                            transaction, state,
                        ).map_err(|_| JournalError::ProtectedBoundary),
                    RecordNamespace::PublisherAuthority => {
                        if !state.keys().any(|(namespace, _)| {
                            *namespace == RecordNamespace::CliAuthorizationTime
                        }) {
                            return Err(JournalError::ProtectedBoundary);
                        }
                        provider_initial_issuance_data::require_git_coverage_initial_from_state_v1(
                            transaction, state,
                        ).map_err(|_| JournalError::ProtectedBoundary)
                    }
                    _ => Err(JournalError::ProtectedBoundary),
                };
            }

            // The only new durable work in this first profile is its sole existing
            // three-PUT account successor. The shared account codec validates its
            // relation; the genuine store/capture performs authority and CAS.
            // No earlier Operation/Effect can coexist with the audited birth, so
            // this never reclassifies an original negative cleanup as NEW work.
            provider_policy_data::require_coverage_native_account_transaction(transaction)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if transaction.records().get(1).is_none_or(|record| {
                state.keys().any(|(namespace, key)| {
                    *namespace == record.namespace() && key.as_slice() == record.key()
                })
            }) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
            }

        pub(super) fn require_mount_transition_read_v1<P>(
            read: aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, P>,
            mount_denied: bool,
            state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transaction: &JournalTransaction,
        ) -> Result<(), JournalError> {
            if !transaction.records().iter()
                .any(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
            {
                return Ok(());
            }
            let durable = has_durable_owner_fence_v1(state);
            if !mount_denied && !durable {
                return Ok(());
            }
            if durable {
                // The first profile requires the complete Source history to be
                // empty before this fence. No earlier debt can be hidden here.
                return Err(JournalError::ProtectedBoundary);
            }
            super::validate_transaction(transaction, read.limits())?;
            aos_sandbox_ledger_replay::git_coverage_prefix::require_mount_original_source_cleanup_v1(
                state, transaction,
            ).map_err(JournalError::from)
            }

        pub(super) fn require_storage_transition_read_v1<P>(
            read: aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, P>,
            state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            transaction: &JournalTransaction,
        ) -> Result<(), JournalError> {
            if !has_durable_owner_fence_v1(state)
                || read.protected_view().is_none_or(|location| {
                    location.name() != "storage-state.journal"
                })
            {
                return Ok(());
            }
            if transaction.records().iter().any(|record| matches!(record.namespace(),
                RecordNamespace::DesiredState
                    | RecordNamespace::Operation
                    | RecordNamespace::Effect
                    | RecordNamespace::AuthorityPublication
                    | RecordNamespace::StorageCatalogReservation
                    | RecordNamespace::StorageCatalogTransition
                    | RecordNamespace::StorageCatalogHead
                    | RecordNamespace::StorageRuntimeConfiguration
                    | RecordNamespace::StorageWorkspacePublicationIntent
                    | RecordNamespace::StorageWorkspacePinAttempt
                    | RecordNamespace::StorageCatalogPreparation
                    | RecordNamespace::StorageWorkspacePinRepairIntent
                    | RecordNamespace::StorageResolverPolicyFloor
                    | RecordNamespace::StorageGuestRootPublicationAttempt))
            {
                // The permanent Storage fence is appended only after the genuine
                // complete history/census is empty. It cannot cover earlier debt.
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
            }
    };
}
