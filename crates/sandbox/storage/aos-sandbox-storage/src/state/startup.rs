//! Retained State startup through the same protected decoder and validators.
//!
//! The ordinary adapter and paid startup share their complete load/validation
//! engine. This module keeps the actual Native opener and Journal resident until
//! every schema, initialization and original-currentness post has succeeded.

use super::*;

pub(super) struct LoadedStorageStateV1 {
    records: BTreeMap<[u8; 16], DurableRecord>,
    catalog_transitions: StorageCatalogTransitionProvider,
    runtime_configuration: Option<ObjectDigest>,
    resolver_policy_floor: Option<StorageResolverPolicyFloorV1>,
    publication_intents: BTreeMap<[u8; 16], StorageWorkspacePublicationIntentV1>,
    pin_attempts: BTreeMap<[u8; 16], WorkspacePinAttemptV1>,
    repair_intents: BTreeMap<[u8; 16], StorageWorkspacePinRepairIntentV1>,
    guest_root_attempts: BTreeMap<[u8; 16], GuestRootPublicationAttemptV2>,
    atomic_snapshots: BTreeMap<[u8; 16], AtomicDatasetSnapshotRecordV1>,
    repair_guards: BTreeMap<[u8; 16], repair_guard::StorageRepairGuardRecordV1>,
}

impl LoadedStorageStateV1 {
    pub(super) fn load(
        journal: &Journal,
        key: &StorageStateKey,
        minimum_generation: u64,
    ) -> Result<Self, StorageStateError> {
        let records = load_durable_records(&journal, &key)?;
        let runtime_configuration = load_runtime_configuration(&journal, &key)?;
        let resolver_policy_floor = load_resolver_policy_floor(&journal, &key)?;
        let publication_intents = load_publication_intents(&journal, &key)?;
        let pin_attempts = load_attempts(&journal, key.key_id, &key.secret)?;
        let repair_intents = load_repair_intents(&journal, key.key_id, &key.secret)?;
        let guest_root_attempts = load_guest_root_attempts(&journal, &key)?;
        let atomic_snapshots = load_atomic_snapshot_records(&journal, &key)?;
        let repair_guards = repair_guard::load(&journal, &key)?;
        let catalog_transitions =
            StorageCatalogTransitionProvider::load(&journal, key.key_id, &key.secret)?;
        let latest_generation = latest_generation(&records).max(
            catalog_transitions
                .head_binding()
                .map_or(0, CatalogBindingV1::generation),
        );
        if latest_generation < minimum_generation {
            return Err(StorageStateError::Rollback);
        }
        validate_durable_records(&records, &catalog_transitions, &key)?;
        if records
            .keys()
            .any(|operation| atomic_snapshots.contains_key(operation))
        {
            return Err(StorageStateError::CorruptRecord);
        }
        validate_atomic_snapshot_catalog_join(&atomic_snapshots, &catalog_transitions)?;
        catalog_transitions
            .validate_operation_set(records.keys().chain(atomic_snapshots.keys()).copied())?;
        validate_publication_intent_set(&records, &publication_intents)?;
        validate_repair_intent_set(
            &journal,
            &records,
            &publication_intents,
            &pin_attempts,
            &repair_intents,
        )?;
        validate_guest_root_attempt_set(
            &journal,
            &records,
            &publication_intents,
            &guest_root_attempts,
        )?;
        Ok(Self {
            records,
            catalog_transitions,
            runtime_configuration,
            resolver_policy_floor,
            publication_intents,
            pin_attempts,
            repair_intents,
            guest_root_attempts,
            atomic_snapshots,
            repair_guards,
        })
    }

    pub(super) fn into_store(self, journal: Journal, key: StorageStateKey) -> StorageTransactionStore {
        StorageTransactionStore {
            journal,
            key,
            records: self.records,
            catalog_transitions: self.catalog_transitions,
            runtime_configuration: self.runtime_configuration,
            resolver_policy_floor: self.resolver_policy_floor,
            receiving_prepare_policy_append: None,
            receiving_preparation_append: None,
            publication_intents: self.publication_intents,
            pin_attempts: self.pin_attempts,
            repair_intents: self.repair_intents,
            guest_root_attempts: self.guest_root_attempts,
            atomic_snapshots: self.atomic_snapshots,
            repair_guards: self.repair_guards,
            startup_native: None,
            startup_mutations: None,
            recovery_mutations: recovery_mutation::StorageRecoveryMutationCaptureV1::new(),
            commit_failed: false,
            #[cfg(test)]
            fail_after_next_journal_commit: false,
        }
    }
}

use aos_sandbox_controller_domain::journal::{
    CapturedJournalOpenModeV1, ProtectedJournalPreopenReplayExtentV1,
    StorageStateCapturedJournalOpenV1,
};
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

#[derive(Debug, thiserror::Error)]
enum DemandError {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Journal(#[from] aos_sandbox_controller_domain::JournalError),
}

#[derive(Clone, Copy)]
enum Failure {
    Native,
    Demand,
    Decode,
    Validation,
    Initialization,
    Names,
    Current,
    Closed,
}

/// Owns the actual staged writer through upper authentication and initialization.
pub(crate) struct StorageStateStartupV1 {
    native: Option<StorageStateCapturedJournalOpenV1>,
    key: Option<StorageStateKey>,
    opened: Option<(Journal, aos_sandbox_controller_domain::RecoveryReport)>,
    recovery: Option<aos_sandbox_controller_domain::RecoveryReport>,
    loaded: Option<Result<LoadedStorageStateV1, StorageStateError>>,
    schema: Option<Result<ResourceVector, AccountingError>>,
    initialization_demand: Option<Result<ResourceVector, DemandError>>,
    store: Option<StorageTransactionStore>,
    validation: Option<Result<(), StorageStateError>>,
    initialization: Option<Result<(), StorageStateError>>,
    names: Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
    names_originals: aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1,
    current: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    first: Option<Failure>,
    entered: bool,
    taken: bool,
}

impl StorageStateStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            native: Some(StorageStateCapturedJournalOpenV1::new()),
            key: None,
            opened: None,
            recovery: None,
            loaded: None,
            schema: None,
            initialization_demand: None,
            store: None,
            validation: None,
            initialization: None,
            names: None,
            names_originals: aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            current: None,
            first: None,
            entered: false,
            taken: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            Failure::Native => self.native.as_ref().and_then(StorageStateCapturedJournalOpenV1::failure),
            Failure::Demand => self.schema.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.initialization_demand.as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::Decode => self.loaded.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Validation => self.validation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Initialization => self.store.as_ref()
                .and_then(|store| store.startup_native.as_ref())
                .and_then(aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1::failure)
                .or_else(|| self.initialization.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::Names => self.names_originals.failure().or_else(|| self.names.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error)),
            Failure::Current => self.current.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Closed => None,
        };
        cause.or(Some(&aos_sandbox_controller_domain::StorageReceivingClosedV1))
    }

    pub(crate) fn open_once_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        mode: CapturedJournalOpenModeV1,
        key: &mut Option<StorageStateKey>,
        minimum_generation: u64,
        configuration_binding: ObjectDigest,
        genesis_generation: u64,
        genesis_catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<(), StorageStateError> {
        if self.entered || self.taken || self.first.is_some() {
            self.first.get_or_insert(Failure::Closed);
            // No original caller key is taken on a repeated or closed entry.
            return Err(StorageStateError::Receiving);
        }
        self.entered = true;
        self.key = key.take();
        if self.key.is_none() {
            self.first = Some(Failure::Closed);
            return Err(StorageStateError::Receiving);
        }
        let lower_result = self.open_native_once(receiving, mode, genesis_catalogs);
        if lower_result.is_err() {
            return Err(StorageStateError::Receiving);
        }
        self.decode_once(if mode == CapturedJournalOpenModeV1::ExistingOnly {
            minimum_generation
        } else {
            0
        });
        if self.first.is_none() {
            self.initialize_once(mode, minimum_generation, configuration_binding,
                genesis_generation, genesis_catalogs);
        }
        // These independent posts are owed even after a domain decoder or
        // actual initialization refusal. Earlier native/domain causes win.
        let journal = self.store.as_ref().map(|store| &store.journal)
            .or_else(|| self.opened.as_ref().map(|(journal, _)| journal));
        self.names = journal.map(|journal|
            journal.validate_held_protected_names_retaining(&mut self.names_originals));
        if !matches!(self.names, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Names);
        }
        self.current = Some(receiving.require_startup_current_v1());
        if !matches!(self.current, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Current);
        }
        if self.first.is_some() {
            return Err(StorageStateError::Receiving);
        }

        Ok(())
    }

    fn open_native_once(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        mode: CapturedJournalOpenModeV1,
        genesis_catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<(), ()> {
        let Some(native) = self.native.as_mut() else {
            self.first = Some(Failure::Closed);
            return Err(());
        };
        let mut guard = receiving.borrow_state_startup_once_v1(native).map_err(|_| {
            self.first = Some(Failure::Native);
        })?;
        if guard.prepare_once_v1(journal_limits(), mode).is_err() {
            self.first = Some(Failure::Native);
            return Err(());
        }
        let Some(extent) = guard.captured_extent_v1() else {
            self.first = Some(Failure::Native);
            return Err(());
        };
        // Compute BOTH upper bounds before replay closes the captured getter.
        self.schema = Some(schema_demand(extent));
        self.initialization_demand = Some(initialization_demand(extent, genesis_catalogs));
        let (Some(Ok(schema)), Some(Ok(initialization))) =
            (self.schema.as_ref(), self.initialization_demand.as_ref())
        else {
            self.first = Some(Failure::Demand);
            return Err(());
        };
        if guard.reserve_schema_once_v1(*schema).is_err()
            || guard.replay_once_v1().is_err()
            || guard.reserve_initialization_once_v1(*initialization).is_err()
        {
            self.first = Some(Failure::Native);
            return Err(());
        }
        self.opened = match guard.take_opened_once_v1() {
            Ok(opened) => Some(opened),
            Err(_) => {
                self.first = Some(Failure::Native);
                return Err(());
            }
        };
        Ok(())
    }

    fn decode_once(&mut self, minimum_generation: u64) {
        if self.loaded.is_some() || self.store.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return;
        }
        let (Some((journal, _)), Some(key)) = (self.opened.as_ref(), self.key.as_ref()) else {
            self.first.get_or_insert(Failure::Closed);
            return;
        };
        self.loaded = Some(LoadedStorageStateV1::load(journal, key, minimum_generation));
        if matches!(self.loaded, Some(Err(_))) {
            self.first.get_or_insert(Failure::Decode);
            return;
        }
        let (Some(Ok(loaded)), Some((journal, recovery)), Some(key)) =
            (self.loaded.take(), self.opened.take(), self.key.take())
        else {
            std::process::abort();
        };
        self.recovery = Some(recovery);
        self.store = Some(loaded.into_store(journal, key));
        let Some(store) = self.store.as_ref() else {
            std::process::abort();
        };
        self.validation = Some(store.validate_loaded_state_v1());
        if matches!(self.validation, Some(Err(_))) {
            self.first.get_or_insert(Failure::Validation);
        }
    }

    fn initialize_once(
        &mut self,
        mode: CapturedJournalOpenModeV1,
        minimum_generation: u64,
        configuration_binding: ObjectDigest,
        genesis_generation: u64,
        genesis_catalogs: &[ResolvedCatalogCommitmentV1],
    ) {
        let Some(store) = self.store.as_mut() else {
            self.first.get_or_insert(Failure::Closed);
            return;
        };
        self.initialization = Some((|| {
            if mode == CapturedJournalOpenModeV1::ExistingOnly {
                store.validate_runtime_restart(configuration_binding, genesis_generation, genesis_catalogs)?;
            } else if store.is_strictly_unused() {
                if genesis_generation < minimum_generation {
                    return Err(StorageStateError::Rollback);
                }
                store.startup_native = Some(aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1::new());
                store.initialize_runtime_from_protected_snapshot(
                    configuration_binding, genesis_generation, genesis_catalogs,
                )?;
            } else {
                store.enforce_minimum_generation(minimum_generation)?;
            }
            Ok(())
        })());
        if matches!(self.initialization, Some(Err(_))) {
            self.first.get_or_insert(Failure::Initialization);
        }
    }

    pub(crate) fn store(&self) -> Option<&StorageTransactionStore> {
        if self.first.is_some() || self.taken { None } else { self.store.as_ref() }
    }

    // Enclosing startup invokes this after State's actual restart/quiescence
    // gates, while the same normal Store remains resident on this attempt.
    pub(crate) fn settle_native_once_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageStateError> {
        if self.first.is_some() || self.taken || self.store.is_none() {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageStateError::Receiving);
        }
        let Some(native) = self.native.take() else {
            self.first = Some(Failure::Closed);
            return Err(StorageStateError::Receiving);
        };
        if let Err(native) = receiving.settle_state_native_opening_once_v1(native) {
            self.native = Some(native);
            self.first = Some(Failure::Current);
            return Err(StorageStateError::Receiving);
        }
        self.names_originals.settle_positive_once_v1();
        Ok(())
    }

    pub(crate) fn take_store_once_v1(&mut self) -> Option<StorageTransactionStore> {
        if self.first.is_some() || !self.entered || self.taken || self.native.is_some() {
            return None;
        }
        self.taken = true;
        self.store.take()
    }
}

fn schema_demand(extent: &ProtectedJournalPreopenReplayExtentV1)
    -> Result<ResourceVector, AccountingError>
{
    crate::receiving_demand::startup_journal_model_demand_v1(
        extent,
        std::mem::size_of::<DurableRecord>()
            + std::mem::size_of::<StorageWorkspacePublicationIntentV1>()
            + std::mem::size_of::<WorkspacePinAttemptV1>()
            + std::mem::size_of::<StorageWorkspacePinRepairIntentV1>()
            + std::mem::size_of::<GuestRootPublicationAttemptV2>()
            + std::mem::size_of::<AtomicDatasetSnapshotRecordV1>()
            + std::mem::size_of::<repair_guard::StorageRepairGuardRecordV1>()
            + std::mem::size_of::<StorageCatalogTransitionProvider>(),
        // Complete local/return frames are fixed bytes; dominant decoded row
        // backing is already supplied separately by the same schema recipe.
        std::mem::size_of::<StorageStateStartupV1>()
            + 2 * std::mem::size_of::<LoadedStorageStateV1>(),
        crate::receiving_demand::StorageStartupNamespaceRecipeV1::State,
    )?
        .checked_add(aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(
        "storage-state.journal",
    ).map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?)
}

fn initialization_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    catalogs: &[ResolvedCatalogCommitmentV1],
) -> Result<ResourceVector, DemandError> {
    use crate::receiving_demand::{add, count, multiply};
    use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
    let bytes = catalogs.iter().try_fold(0, |total, catalog|
        add(total, count(catalog.canonical_bytes().len())?))?;
    // The binary inputs expand to fixed-field physical JSON. Sixteen encoded
    // copies cover escaped names, fixed decimal/digest fields and authenticated
    // wrappers;1024 per typed catalog covers its fixed root/input field names.
    let head = add(1024, add(multiply(bytes, 16)?, multiply(count(catalogs.len())?, 1024)?)?)?;
    let head = usize::try_from(head).map_err(|_| AccountingError::ArithmeticOverflow {
        dimension: D::MemoryBytes,
    })?;
    let shapes = [
        RecordShape { key_bytes: RUNTIME_CONFIGURATION_KEY.len(), value_bytes: Some(90) },
        RecordShape { key_bytes: crate::catalog_transition::bootstrap_head_key_bytes_v1(), value_bytes: Some(head) },
    ];
    let append = encoded_transaction_append_bytes(shapes.into_iter())
        .map_err(aos_sandbox_controller_domain::JournalError::from)?;
    let future = extent.native_bytes.checked_add(append)
        .ok_or(aos_sandbox_controller_domain::JournalError::JournalTooLarge)?;
    let forecast = aos_sandbox_controller_domain::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
        extent.limits, future,
    )?;
    let native = forecast.dominant_native_receiving_demand_v1()?;
    let semantic = forecast.dominant_semantic_receiving_demand_v1()?;
    let models = ResourceVector::ZERO
        .with(D::MemoryBytes, add(multiply(bytes, 128)?, multiply(count(catalogs.len())?, 32 * 1024)?)?)
        .with(D::MetadataEntries, multiply(count(catalogs.len())?, 32)?)
        .with(D::StorageBytes, future)
        .with(D::LogBytes, append);
    let append_names = aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(
        "storage-state.journal",
    )?;
    Ok(native.checked_add(semantic)?.checked_add(models)?.checked_add(append_names)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aos-storage-state-prefix-{}-{sequence}", std::process::id(),
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn malformed_state_keeps_actual_writer_and_same_decoder_error_on_reentry() {
        let directory = TestDirectory::new();
        let (mut journal, recovery) = Journal::open(
            directory.0.join("state"), journal_limits(),
        ).unwrap();
        let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::StorageRuntimeConfiguration,
            RUNTIME_CONFIGURATION_KEY.to_vec(), vec![0],
        )]).unwrap();
        journal.commit(&transaction).unwrap();
        let before = journal.snapshot_sequence();
        // This ordinary native seed supplies DATA for the shared upper decoder,
        // not a PID1 original, paid guard or positive receiving factory.
        let mut attempt = StorageStateStartupV1::new();
        attempt.opened = Some((journal, recovery));
        attempt.key = Some(StorageStateKey::new([2; 16], [3; 32]).unwrap());

        attempt.decode_once(0);
        let first = std::ptr::from_ref(attempt.failure().unwrap()
            .downcast_ref::<StorageStateError>().unwrap());
        attempt.decode_once(0);

        assert_eq!(first, std::ptr::from_ref(attempt.failure().unwrap()
            .downcast_ref::<StorageStateError>().unwrap()));
        assert_eq!(attempt.opened.as_ref().unwrap().0.snapshot_sequence(), before);
        assert!(attempt.key.is_some());
        assert!(attempt.store.is_none());
        assert!(attempt.take_store_once_v1().is_none());
    }

    #[test]
    fn validated_empty_state_stays_resident_until_actual_native_settlement() {
        let directory = TestDirectory::new();
        let (journal, recovery) = Journal::open(directory.0.join("state"), journal_limits()).unwrap();
        let mut attempt = StorageStateStartupV1::new();
        attempt.opened = Some((journal, recovery));
        attempt.key = Some(StorageStateKey::new([2; 16], [3; 32]).unwrap());

        attempt.decode_once(0);

        assert!(attempt.failure().is_none());
        assert!(attempt.store.as_ref().unwrap().is_strictly_unused());
        assert!(attempt.take_store_once_v1().is_none());
        assert!(attempt.store.is_some());
        assert!(attempt.native.is_some());
        assert!(attempt.recovery.is_some());
    }

    #[test]
    fn late_authenticated_key_id_error_preserves_original_input() {
        use hmac::Mac as _;
        use super::super::tests::{catalog, digest, initialize, key};

        let directory = tempfile::TempDir::new().unwrap();
        let mut store = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        initialize(&mut store, &catalog);
        assert!(matches!(store.begin([91; 16], digest(92), &catalog).unwrap(),
            BeginStorageTransaction::Prepared { .. }));
        let mut bytes = encode_record(store.records.get(&[91; 16]).unwrap(), &store.key).unwrap();
        let body_end = bytes.len() - MAC_BYTES;
        bytes[body_end - 16] ^= 1;
        let mut mac = HmacSha256::new_from_slice(&store.key.secret).unwrap();
        mac.update(RECORD_DOMAIN);
        mac.update(&bytes[..body_end]);
        bytes[body_end..].copy_from_slice(&mac.finalize().into_bytes());
        let expected = bytes.clone();
        let transaction = JournalTransaction::new([96; 16], vec![JournalRecord::put(
            RecordNamespace::Operation, vec![97; 16], bytes,
        )]).unwrap();
        store.journal.commit(&transaction).unwrap();
        let sequence = store.journal.snapshot_sequence();

        let failure = match LoadedStorageStateV1::load(&store.journal, &store.key, 0) {
            Err(failure) => failure,
            Ok(_) => panic!("authenticated embedded key-ID mismatch must fail"),
        };

        assert!(matches!(failure, StorageStateError::CorruptRecord));
        assert_eq!(store.journal.get(RecordNamespace::Operation, &[97; 16]),
            Some(expected.as_slice()));
        assert_eq!(store.journal.snapshot_sequence(), sequence);
    }

}
