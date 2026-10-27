//! Shares ordinary and original-B Cache bootstrap import effects.
//!
//! One retained engine owns requested/existing models, the exact missing
//! transaction, preflight/native/readback Results and final reopened original.
//! Ordinary callers move their actual first error; the selected original keeps
//! the same engine in its startup parent through independent B bookends.

use super::*;
use crate::journal::{CommitResult, ProtectedJournalPreflight};

type ImportMap = BTreeMap<ObjectDigest, Vec<u8>>;
type OpenedSource = (Journal, RecoveryReport);

const CLOSED_IMPORT: CacheReplayControllerBootstrapErrorV1 =
    CacheReplayControllerBootstrapErrorV1::InvalidSource;

#[derive(Clone, Copy)]
enum ImportFailure {
    Requested,
    Opening,
    Existing,
    Relation,
    Transaction,
    Preflight,
    Effect,
    Commit,
    Readback,
    SourcePost,
    FinalOpening,
    FinalModels,
    FinalRelation,
    FinalPost,
}

#[derive(Default)]
struct CacheBootstrapImportEngineV1 {
    requested: Option<Result<ImportMap, CacheReplayControllerBootstrapErrorV1>>,
    opening: Option<Result<OpenedSource, CacheReplayControllerBootstrapErrorV1>>,
    existing: Option<Result<ImportMap, CacheReplayControllerBootstrapErrorV1>>,
    relation: Option<Result<(), CacheReplayControllerBootstrapErrorV1>>,
    transaction: Option<Result<Option<JournalTransaction>, CacheReplayControllerBootstrapErrorV1>>,
    preflight: Option<Result<ProtectedJournalPreflight, JournalError>>,
    effect: Option<Result<(), CacheReplayControllerBootstrapErrorV1>>,
    native: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<(), CacheReplayControllerBootstrapErrorV1>>,
    source_post: Option<Result<(), JournalError>>,
    final_opening: Option<Result<OpenedSource, CacheReplayControllerBootstrapErrorV1>>,
    final_models: Option<Result<ImportMap, CacheReplayControllerBootstrapErrorV1>>,
    final_relation: Option<Result<(), CacheReplayControllerBootstrapErrorV1>>,
    final_post: Option<Result<(), JournalError>>,
    final_report: Option<RecoveryReport>,
    first: Option<ImportFailure>,
}

// Each whole result is parked before its success projection. Selection affects
// error custody only; ordinary and selected use the same semantic/effect engine.
macro_rules! import_step {
    ($owner:ident, $site:ident, $slot:ident, $returned:expr) => {{
        $owner.first = Some(ImportFailure::$site);
        $owner.$slot = Some($returned);
        $owner.$slot.as_mut().and_then(|result| result.as_mut().ok()).ok_or(())?
    }};
}

impl CacheBootstrapImportEngineV1 {
    fn decode_requested(&mut self, bundle: &[u8]) -> Result<(), ()> {
        if self.requested.is_some() {
            return Err(());
        }
        import_step!(self, Requested, requested, decode_controller_bundle(bundle));
        self.first = None;
        Ok(())
    }

    fn import_opened<const RETAINED: bool>(&mut self, bundle: &[u8]) -> Result<(), ()> {
        let requested = self.requested.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
        self.first = Some(ImportFailure::Opening);
        let (journal, report) = self.opening.as_mut().and_then(|result| result.as_mut().ok()).ok_or(())?;
        let existing = import_step!(self, Existing, existing, read_source_records(journal));
        import_step!(self, Relation, relation,
            if report.truncated_bytes != 0
                || report.committed_transactions > existing.len()
                || (!existing.is_empty() && report.committed_transactions == 0)
                || report.committed_records != existing.len()
                || existing.iter().any(|(partition, bytes)| requested.get(partition) != Some(bytes))
            {
                Err(CacheReplayControllerBootstrapErrorV1::InvalidSource)
            } else { Ok(()) });
        let transaction = import_step!(self, Transaction, transaction, (|| {
            let missing = requested.iter()
                .filter(|(partition, _)| !existing.contains_key(partition))
                .map(|(partition, bytes)| JournalRecord::put(
                    RecordNamespace::DesiredState, source_key(*partition), bytes.clone(),
                )).collect::<Vec<_>>();
            if missing.is_empty() {
                return Ok(None);
            }
            let digest = Sha256::new()
                .chain_update(b"aos.sandbox.cache.controller-source-transaction.v1\0")
                .chain_update(bundle).finalize();
            let transaction_id: [u8; 16] = digest[..16].try_into()
                .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
            JournalTransaction::new(transaction_id, missing)
                .map(Some).map_err(JournalError::from).map_err(CacheReplayControllerBootstrapErrorV1::from)
        })());
        if let Some(transaction) = transaction {
            // The authority borrows the same actual retained writer. The fixed
            // token is parked before its final effect-boundary validation.
            self.first = Some(ImportFailure::Effect);
            self.effect = Some(Ok(()));
            let authority = journal.claim_cache_authority_v1();
            let mut authority = match authority {
                Ok(authority) => authority,
                Err(cause) => {
                    self.effect = Some(Err(cause.into()));
                    return Err(());
                }
            };
            for (partition, _) in requested.iter().filter(|(partition, _)| !existing.contains_key(partition)) {
                self.effect = Some(authority.get(&source_key(*partition))
                    .map_err(CacheReplayControllerBootstrapErrorV1::from).and_then(|value| {
                        if value.is_none() { Ok(()) }
                        else { Err(CacheReplayControllerBootstrapErrorV1::InvalidSource) }
                    }));
                if !matches!(self.effect, Some(Ok(()))) { return Err(()); }
            }
            let preflight = import_step!(self, Preflight, preflight,
                authority.preflight_transactions(std::slice::from_ref(transaction)));
            import_step!(self, Effect, effect,
                authority.validate_preflight_for_effect(preflight, std::slice::from_ref(transaction))
                    .map_err(CacheReplayControllerBootstrapErrorV1::from));
            self.first = Some(ImportFailure::Commit);
            self.native = Some(authority.commit(transaction));
            let committed = matches!(self.native, Some(Ok(_)));
            if RETAINED || committed {
                // A selected native Err cannot suppress its independent same
                // writer negative readback; ordinary preserves its old stop.
                self.readback = Some((|| {
                    for (partition, bytes) in requested.iter()
                        .filter(|(partition, _)| !existing.contains_key(partition))
                    {
                        if authority.get(&source_key(*partition))? != Some(bytes.as_slice()) {
                            return Err(CacheReplayControllerBootstrapErrorV1::InvalidSource);
                        }
                    }
                    Ok(())
                })());
            }
            if !committed { return Err(()); }
            self.first = Some(ImportFailure::Readback);
            if !matches!(self.readback, Some(Ok(()))) { return Err(()); }
        }
        self.first = None;
        Ok(())
    }

    fn initial_source_post(&mut self) -> Result<(), ()> {
        if self.source_post.is_some() { return Err(()); }
        let first = self.first;
        self.source_post = self.opening.as_ref().and_then(|result| result.as_ref().ok())
            .map(|(journal, _)| {
                journal.ensure_protected_authority()?;
                journal.require_protected_names_current()
            });
        if first.is_some() { return Err(()); }
        if !matches!(self.source_post, Some(Ok(()))) {
            self.first = Some(ImportFailure::SourcePost);
            return Err(());
        }
        Ok(())
    }

    fn verify_reopened(&mut self) -> Result<(), ()> {
        let requested = self.requested.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
        self.first = Some(ImportFailure::FinalOpening);
        let (journal, report) = self.final_opening.as_mut()
            .and_then(|result| result.as_mut().ok()).ok_or(())?;
        let records = import_step!(self, FinalModels, final_models,
            validate_controller_cache_source(journal, report));
        import_step!(self, FinalRelation, final_relation,
            if records == requested { Ok(()) }
            else { Err(CacheReplayControllerBootstrapErrorV1::InvalidSource) });
        self.final_report = Some(*report);
        self.first = None;
        Ok(())
    }

    fn final_source_post(&mut self) -> Result<(), ()> {
        if self.final_post.is_some() { return Err(()); }
        let first = self.first;
        self.final_post = self.final_opening.as_ref().and_then(|result| result.as_ref().ok())
            .map(|(journal, _)| {
                journal.ensure_protected_authority()?;
                journal.require_protected_names_current()
            });
        if first.is_some() { return Err(()); }
        if !matches!(self.final_post, Some(Ok(()))) {
            self.first = Some(ImportFailure::FinalPost);
            return Err(());
        }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        macro_rules! cause {
            ($slot:ident) => { self.$slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)) };
        }
        match self.first? {
            ImportFailure::Requested => cause!(requested),
            ImportFailure::Opening => cause!(opening),
            ImportFailure::Existing => cause!(existing),
            ImportFailure::Relation => cause!(relation),
            ImportFailure::Transaction => cause!(transaction),
            ImportFailure::Preflight => cause!(preflight),
            ImportFailure::Effect => cause!(effect),
            ImportFailure::Commit => cause!(native),
            ImportFailure::Readback => cause!(readback),
            ImportFailure::SourcePost => cause!(source_post),
            ImportFailure::FinalOpening => cause!(final_opening),
            ImportFailure::FinalModels => cause!(final_models),
            ImportFailure::FinalRelation => cause!(final_relation),
            ImportFailure::FinalPost => cause!(final_post),
        }
    }

    fn take_ordinary_failure(&mut self) -> CacheReplayControllerBootstrapErrorV1 {
        macro_rules! cause {
            ($slot:ident) => { self.$slot.take().and_then(Result::err)
                .map(CacheReplayControllerBootstrapErrorV1::from) };
        }
        let cause = match self.first {
            Some(ImportFailure::Requested) => cause!(requested),
            Some(ImportFailure::Opening) => cause!(opening),
            Some(ImportFailure::Existing) => cause!(existing),
            Some(ImportFailure::Relation) => cause!(relation),
            Some(ImportFailure::Transaction) => cause!(transaction),
            Some(ImportFailure::Preflight) => cause!(preflight),
            Some(ImportFailure::Effect) => cause!(effect),
            Some(ImportFailure::Commit) => cause!(native),
            Some(ImportFailure::Readback) => cause!(readback),
            Some(ImportFailure::FinalOpening) => cause!(final_opening),
            Some(ImportFailure::FinalModels) => cause!(final_models),
            Some(ImportFailure::FinalRelation) => cause!(final_relation),
            _ => None,
        };
        cause.unwrap_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)
    }
}

pub(super) fn import_ordinary(
    uid: u32,
    bundle: &[u8],
) -> Result<RecoveryReport, CacheReplayControllerBootstrapErrorV1> {
    let mut engine = CacheBootstrapImportEngineV1::default();
    let returned = (|| {
        engine.decode_requested(bundle)?;
        engine.opening = Some(Journal::open_cache_ordinary_role_v1(
            Path::new(CONTROLLER_CACHE_ROOT), CONTROLLER_CACHE_JOURNAL,
            controller_cache_journal_limits(), uid,
            crate::journal::CacheOrdinaryOpenV1::Creating,
        ).map_err(CacheReplayControllerBootstrapErrorV1::from));
        engine.import_opened::<false>(bundle)?;
        drop(engine.opening.take());
        engine.final_opening = Some(Journal::open_cache_ordinary_role_v1(
            Path::new(CONTROLLER_CACHE_ROOT), CONTROLLER_CACHE_JOURNAL,
            controller_cache_journal_limits(), uid,
            crate::journal::CacheOrdinaryOpenV1::Creating,
        ).map_err(CacheReplayControllerBootstrapErrorV1::from));
        engine.verify_reopened()
    })();
    if returned.is_err() { return Err(engine.take_ordinary_failure()); }
    engine.final_report.ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)
}

#[cfg(target_os = "linux")]
mod selected {
    use super::*;
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    use aos_sandbox_broker::controller_receiving::{ControllerCachePreBankImportLoanV1,
        ControllerReceivingErrorV1, profile::ControllerProfileErrorV1};
    use crate::journal::CacheNativeStageV1;
    use crate::protected_owner::{
        CacheConstructionOriginalsV1,
        CacheConstructionReceivingV1, CacheConstructionOwnerV1,
    };
    use crate::protected_owner::CacheReplayManifestGeometryV1;
    use crate::recovery::{
        CacheReplayRepresentationPhaseV1, general_replay_representation_bound_v1,
    };

    #[derive(Default)]
    struct ImportProfilePhase {
        entry: Option<Result<(), ControllerReceivingErrorV1>>,
        post: Option<Result<(), ControllerProfileErrorV1>>,
    }

    impl ImportProfilePhase {
        fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
            error(self.entry.as_ref()).or_else(|| error(self.post.as_ref()))
        }
    }

    #[derive(Clone, Copy)]
    enum SelectedFailure {
        PhaseBefore(usize),
        Geometry,
        Pricing,
        Decode,
        Native(usize),
        Import,
        Verify,
        PhaseAfter(usize),
    }

    /// Keeps one optional startup import under the actual original Controller B.
    pub struct CacheSelectedBootstrapImportV1 {
        originals: CacheConstructionOriginalsV1,
        geometry: Option<Result<import_geometry::CacheBootstrapImportGeometryV1,
            CacheReplayControllerBootstrapErrorV1>>,
        pricing: Option<Result<ResourceVector, CacheReplayControllerBootstrapErrorV1>>,
        stages: [Option<CacheNativeStageV1>; 2],
        phases: [ImportProfilePhase; 2],
        engine: CacheBootstrapImportEngineV1,
        first: Option<SelectedFailure>,
        started: bool,
    }

    impl CacheSelectedBootstrapImportV1 {
        /// Creates empty custody for the actual two-phase native import.
        pub fn new() -> Self {
            Self {
                originals: CacheConstructionOriginalsV1::new(),
                geometry: None, pricing: None, stages: [None, None],
                phases: std::array::from_fn(|_| ImportProfilePhase::default()),
                engine: CacheBootstrapImportEngineV1::default(),
                first: None, started: false,
            }
        }

        /// Imports and reopens the fixed Bootstrap writer under its real loan.
        ///
        /// # Errors
        /// Borrows the retained original model, opening, append, receiving or
        /// independently owed profile/native post cause without dropping it.
        pub fn import_once(
            &mut self,
            loan: &mut ControllerCachePreBankImportLoanV1<'_>,
            uid: u32,
            bundle: &[u8],
            semantic_supplement: Option<ResourceVector>,
            upper_forwarding_bytes: usize,
        ) -> Result<RecoveryReport, &(dyn std::error::Error + 'static)> {
            if self.started { return Err(&CLOSED_IMPORT); }
            self.started = true;
            if self.run_phase(loan, 0, uid, bundle, semantic_supplement, upper_forwarding_bytes).is_err() {
                return Err(self.failure().unwrap_or(&CLOSED_IMPORT));
            }
            // Full actual Source/profile/control comparisons and clean Ended
            // succeeded. Only now dispose the positive original Native writer
            // and stage before the required durable reopen; copied Results and
            // models remain resident, and no ledger charge is refunded.
            drop(self.engine.opening.take());
            drop(self.stages[0].take());
            if self.run_phase(loan, 1, uid, bundle, semantic_supplement, upper_forwarding_bytes).is_err() {
                return Err(self.failure().unwrap_or(&CLOSED_IMPORT));
            }
            let report = self.engine.final_report
                .ok_or(&CLOSED_IMPORT as &(dyn std::error::Error + 'static))?;
            // The complete second operation is positive too; ordinary startup
            // must be able to open this same immutable source later. Negative
            // stages never enter this disposal path or replace these slots.
            drop(self.engine.final_opening.take());
            drop(self.stages[1].take());
            Ok(report)
        }

        /// Reports only the actual selected negative upper-quote frontier.
        #[doc(hidden)]
        pub fn construction_semantic_supplement_failure_is_selected_v1(&self) -> bool {
            matches!(self.failure().and_then(|cause| cause.downcast_ref::<crate::journal::CacheConstructionStageErrorV1>()),
                Some(crate::journal::CacheConstructionStageErrorV1::Journal(crate::journal::JournalError::DeferredUpperSemanticQuote)))
        }

        fn import_initial(&mut self, uid: u32, bundle: &[u8],
            receiving: &CacheConstructionReceivingV1<'_, '_, '_, '_, ()>) -> Result<(), ()> {
            self.first = Some(SelectedFailure::Geometry);
            self.geometry = Some(import_geometry::CacheBootstrapImportGeometryV1::from_bundle(bundle));
            if !matches!(self.geometry, Some(Ok(_))) { return Err(()); }
            self.raise_models(None, receiving)?;
            self.first = Some(SelectedFailure::Decode);
            self.engine.decode_requested(bundle)?;
            self.first = Some(SelectedFailure::Native(0));
            self.stages[0] = Some(CacheNativeStageV1::new());
            let opened = receiving.open_native_once_v1(
                self.stages[0].as_mut().ok_or(())?,
                aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1::Bootstrap,
                uid, true,
            ).map_err(|_| ())?;
            self.engine.opening = Some(Ok(opened));
            self.raise_models(Some(0), receiving)?;
            self.first = Some(SelectedFailure::Import);
            let primary = self.engine.import_opened::<true>(bundle);
            let post = self.engine.initial_source_post();
            primary?;
            post?;
            self.first = None;
            Ok(())
        }

        fn verify_final(&mut self, uid: u32,
            receiving: &CacheConstructionReceivingV1<'_, '_, '_, '_, ()>) -> Result<(), ()> {
            self.first = Some(SelectedFailure::Native(1));
            self.stages[1] = Some(CacheNativeStageV1::new());
            let opened = receiving.open_native_once_v1(
                self.stages[1].as_mut().ok_or(())?,
                aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1::Bootstrap,
                uid, true,
            ).map_err(|_| ())?;
            self.engine.final_opening = Some(Ok(opened));
            self.raise_models(Some(1), receiving)?;
            self.first = Some(SelectedFailure::Verify);
            let primary = self.engine.verify_reopened();
            let post = self.engine.final_source_post();
            primary?;
            post?;
            self.first = None;
            Ok(())
        }

        fn raise_models(&mut self, native: Option<usize>,
            receiving: &CacheConstructionReceivingV1<'_, '_, '_, '_, ()>) -> Result<(), ()> {
            self.first = Some(SelectedFailure::Pricing);
            let geometry = self.geometry.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
            let journal = match native {
                Some(0) => self.engine.opening.as_ref()
                    .and_then(|result| result.as_ref().ok()).map(|(journal, _)| journal),
                Some(1) => self.engine.final_opening.as_ref()
                    .and_then(|result| result.as_ref().ok()).map(|(journal, _)| journal),
                _ => None,
            };
            self.pricing = Some(import_model_bound(geometry, journal).and_then(|bound| {
                let bytes = std::mem::size_of::<CacheConstructionOriginalsV1>().checked_mul(2)
                    .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheConstructionReceivingV1<'_, '_, '_, '_, ()>>()
                        .checked_mul(2)?))
                    .and_then(|bytes| bytes.checked_add(crate::journal::ConstructionLoanV1::<()>::forwarding_control_bytes_v1()?))
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
                bound.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                    .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)
            }));
            let complete = self.pricing.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(())?;
            receiving.require_import_complete(complete).map_err(|_| ())
        }

        fn run_phase(
            &mut self,
            loan: &mut ControllerCachePreBankImportLoanV1<'_>,
            index: usize,
            uid: u32,
            bundle: &[u8],
            semantic_supplement: Option<ResourceVector>,
            upper_forwarding_bytes: usize,
        ) -> Result<(), ()> {
            if index >= self.phases.len() || self.phases[index].entry.is_some() {
                return Err(());
            }
            self.first = Some(SelectedFailure::PhaseBefore(index));
            self.phases[index].entry = Some(loan.begin_next_native_once());
            if matches!(self.phases[index].entry, Some(Ok(()))) {
                // Keep the permanent DATA owner outside the mutable body for
                // this borrow. It returns before any post or error projection.
                let originals = std::mem::replace(&mut self.originals, CacheConstructionOriginalsV1::new());
                let receiving = CacheConstructionReceivingV1::<()>::import(&originals, loan, semantic_supplement, upper_forwarding_bytes);
                let primary = match index {
                    0 => self.import_initial(uid, bundle, &receiving),
                    1 => self.verify_final(uid, &receiving),
                    _ => Err(()),
                };
                drop(receiving);
                self.originals = originals;
                if primary.is_err() && self.first.is_none() {
                    self.first = Some(SelectedFailure::Import);
                }
            }
            // The actual two-phase lender owns profile/control observations;
            // no upper body outcome can certify or suppress its owed post.
            self.phases[index].post = Some(loan.finish_native_once());
            if self.first.is_none() { self.first = Some(SelectedFailure::PhaseAfter(index)); }
            if !matches!(self.phases[index].entry, Some(Ok(())))
                || !matches!(self.phases[index].post, Some(Ok(())))
                || !matches!(self.first, Some(SelectedFailure::PhaseAfter(_)))
            {
                return Err(());
            }
            self.first = None;
            Ok(())
        }

        /// Borrows the earliest retained original import or post failure.
        pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self.first? {
                SelectedFailure::PhaseBefore(index) | SelectedFailure::PhaseAfter(index) => {
                    self.phases[index].failure()
                }
                SelectedFailure::Geometry => error(self.geometry.as_ref()),
                SelectedFailure::Pricing => error(self.pricing.as_ref()).or_else(|| self.originals.failure()),
                SelectedFailure::Decode | SelectedFailure::Import | SelectedFailure::Verify => self.engine.failure(),
                SelectedFailure::Native(index) => self.originals.failure()
                    .or_else(|| self.stages[index].as_ref().and_then(CacheNativeStageV1::failure)),
            }
        }
    }

    // Actual closed import owners, excluding Runtime's already retained raw
    // credential and the separately charged captured Native source baseline.
    fn import_model_bound(
        geometry: &import_geometry::CacheBootstrapImportGeometryV1,
        journal: Option<&Journal>,
    ) -> Result<ResourceVector, CacheReplayControllerBootstrapErrorV1> {
        let unavailable = || CacheReplayControllerBootstrapErrorV1::InvalidSource;
        let append = usize::try_from(geometry.maximum_native_append_bytes()?).map_err(|_| unavailable())?;
        let future = geometry.maximum_native_append_records();
        let future_slots = future.checked_mul(3).and_then(|rows| rows.checked_add(11)).ok_or_else(unavailable)?;
        let carrier = std::mem::size_of::<(Vec<u8>, Vec<u8>, [usize; 6])>();
        // Native append can retain the new materialized values while the
        // current encoded frame grows/reallocates. Four complete append-byte
        // lanes cover that value owner plus the frame old/new/capture buffers;
        // requested/missing/final semantic maps are the geometry's own terms.
        let native_future = append.checked_mul(4)
            .and_then(|bytes| bytes.checked_add(future_slots.checked_mul(4)?.checked_mul(carrier)?))
            .ok_or_else(unavailable)?;
        let sparse_roots = 3_usize.checked_mul(11).and_then(|rows| rows.checked_mul(carrier)).ok_or_else(unavailable)?;
        let mut memory = geometry.dominant_import_memory_bytes().ok_or_else(unavailable)?
            .checked_add(native_future).and_then(|bytes| bytes.checked_add(sparse_roots))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheSelectedBootstrapImportV1>()))
            .ok_or_else(unavailable)?;
        let mut metadata = geometry.dominant_import_metadata_entries().ok_or_else(unavailable)?
            .checked_add(future_slots.checked_mul(8).ok_or_else(unavailable)?)
            .and_then(|entries| entries.checked_add(64)).ok_or_else(unavailable)?;
        if let Some(journal) = journal {
            let (mut bytes, mut rows) = (0_usize, 0_usize);
            for (_, key, value) in journal.all_records() {
                bytes = bytes.checked_add(key.len())
                    .and_then(|bytes| bytes.checked_add(value.len())).ok_or_else(unavailable)?;
                rows = rows.checked_add(1).ok_or_else(unavailable)?;
            }
            let slots = rows.checked_mul(3).and_then(|rows| rows.checked_add(11)).ok_or_else(unavailable)?;
            // The existing source clone and final reopened records coexist;
            // Native preflight's old/current map copies are separate from the
            // already-live source baseline. Include foreign rows before their
            // semantic rejection, and sparse carrier floors independently.
            let existing = bytes.checked_mul(4)
                .and_then(|bytes| bytes.checked_add(slots.checked_mul(4)?.checked_mul(carrier)?))
                .ok_or_else(unavailable)?;
            memory = memory.checked_add(existing).ok_or_else(unavailable)?;
            metadata = metadata.checked_add(slots.checked_mul(8).ok_or_else(unavailable)?).ok_or_else(unavailable)?;
        }
        let complete = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| unavailable())?)
            .with(D::MetadataEntries, u64::try_from(metadata).map_err(|_| unavailable())?)
            // Only the closed all-missing future append reserves persistent
            // bytes. Existing journal reads/replay do not claim storage again.
            .with(D::StorageBytes, geometry.maximum_native_append_bytes()?);
        let Some(journal) = journal else { return Ok(complete); };

        // Existing rows can contain more quotas than the requested bundle.
        // Borrow their actual source geometry before the first typed decode;
        // classification selects a bound, never substitutes for validation.
        let source = CacheReplayManifestGeometryV1::from_source_journal(
            journal, CacheRecoveryLimitsV1::default(),
        ).map_err(|_| unavailable())?;
        let semantic = match source.genesis_manifest_validation_bound()
            .map_err(|_| unavailable())?
        {
            Some(complete) => complete,
            None => general_replay_representation_bound_v1(
                source.encoded_bytes(), source.partition_bound(),
                CacheReplayRepresentationPhaseV1::ManifestValidation,
            ).map_err(|_| unavailable())?,
        };
        complete.checked_add(semantic).map_err(|_| unavailable())
    }

    #[cfg(all(test, unix))]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        #[test]
        fn held_source_semantic_geometry_is_additional_to_requested_and_native_maps() {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let uid = fs::metadata(directory.path()).unwrap().uid();
            let manifest = super::super::super::import_geometry::tests::manifest();
            let bundle = encode_cache_replay_controller_bundle_v1([manifest.clone()]).unwrap();
            let geometry = import_geometry::CacheBootstrapImportGeometryV1::from_bundle(&bundle).unwrap();
            let without_source = import_model_bound(&geometry, None).unwrap();
            let (mut journal, _) = Journal::open_cache_ordinary_fixture_v1(
                directory.path(),
                crate::journal::CacheOrdinaryFixtureV1::ImportSource,
                controller_cache_journal_limits(),
                uid,
            ).unwrap();
            let transaction = JournalTransaction::new([9; 16], vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                source_key(*decode_controller_bundle(&bundle).unwrap().keys().next().unwrap()),
                manifest,
            )]).unwrap();
            journal.claim_cache_authority_v1()
                .unwrap().commit(&transaction).unwrap();

            let held = CacheReplayManifestGeometryV1::from_source_journal(
                &journal, CacheRecoveryLimitsV1::default(),
            ).unwrap().genesis_manifest_validation_bound().unwrap().unwrap();
            let complete = import_model_bound(&geometry, Some(&journal)).unwrap();

            assert!(complete.get(D::MemoryBytes) >= without_source.get(D::MemoryBytes)
                + held.get(D::MemoryBytes));
            assert!(complete.get(D::MetadataEntries) >= without_source.get(D::MetadataEntries)
                + held.get(D::MetadataEntries));
            assert_eq!(complete.get(D::StorageBytes), without_source.get(D::StorageBytes));
        }
    }

    fn error<T, E: std::error::Error + 'static>(returned: Option<&Result<T, E>>)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        returned.and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

#[cfg(target_os = "linux")]
pub use selected::CacheSelectedBootstrapImportV1;


#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn source_directory() -> (tempfile::TempDir, u32) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        (directory, uid)
    }

    fn open(directory: &Path, uid: u32) -> OpenedSource {
        Journal::open_cache_ordinary_fixture_v1(
            directory,
            crate::journal::CacheOrdinaryFixtureV1::ImportSource,
            controller_cache_journal_limits(),
            uid,
        ).unwrap()
    }

    fn bundle() -> Vec<u8> {
        let manifest = super::super::import_geometry::tests::manifest();
        encode_cache_replay_controller_bundle_v1([manifest]).unwrap()
    }

    fn import_and_reopen<const RETAINED: bool>(
        directory: &Path,
        uid: u32,
        bundle: &[u8],
    ) -> CacheBootstrapImportEngineV1 {
        let mut engine = CacheBootstrapImportEngineV1::default();
        engine.decode_requested(bundle).unwrap();
        engine.opening = Some(Ok(open(directory, uid)));

        engine.import_opened::<RETAINED>(bundle).unwrap();
        engine.initial_source_post().unwrap();
        drop(engine.opening.take());
        engine.final_opening = Some(Ok(open(directory, uid)));
        engine.verify_reopened().unwrap();
        engine.final_source_post().unwrap();
        engine
    }

    #[test]
    fn ordinary_and_retained_engines_import_then_reopen_without_duplicate_append() {
        let bundle = bundle();
        for retained in [false, true] {
            let (directory, uid) = source_directory();
            let first = if retained {
                import_and_reopen::<true>(directory.path(), uid, &bundle)
            } else {
                import_and_reopen::<false>(directory.path(), uid, &bundle)
            };
            assert!(matches!(first.native, Some(Ok(_))));
            assert_eq!(first.final_report.unwrap().committed_transactions, 1);
            assert_eq!(first.final_report.unwrap().committed_records, 1);
            assert!(first.failure().is_none());
            drop(first);

            let second = if retained {
                import_and_reopen::<true>(directory.path(), uid, &bundle)
            } else {
                import_and_reopen::<false>(directory.path(), uid, &bundle)
            };
            assert!(second.native.is_none());
            assert_eq!(second.final_report.unwrap().committed_transactions, 1);
            assert_eq!(second.final_report.unwrap().committed_records, 1);
            assert!(second.failure().is_none());
        }
    }

    #[test]
    fn foreign_source_refusal_keeps_writer_and_independent_name_post_without_append() {
        let (directory, uid) = source_directory();
        let bundle = bundle();
        let (mut journal, _) = open(directory.path(), uid);
        let foreign = JournalTransaction::new([7; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, b"foreign".to_vec(), vec![1],
        )]).unwrap();
        journal.claim_cache_authority_v1()
            .unwrap().commit(&foreign).unwrap();
        drop(journal);
        let before = fs::read(directory.path().join("source.journal")).unwrap();
        let mut engine = CacheBootstrapImportEngineV1::default();
        engine.decode_requested(&bundle).unwrap();
        engine.opening = Some(Ok(open(directory.path(), uid)));

        assert!(engine.import_opened::<true>(&bundle).is_err());
        assert!(engine.initial_source_post().is_err());

        assert!(matches!(engine.first, Some(ImportFailure::Existing)));
        assert!(matches!(engine.source_post, Some(Ok(()))));
        assert!(engine.failure().is_some());
        assert!(engine.opening.as_ref().unwrap().is_ok());
        assert!(engine.native.is_none());
        assert_eq!(fs::read(directory.path().join("source.journal")).unwrap(), before);
    }

    #[test]
    fn changed_source_name_retains_native_result_and_original_writer() {
        let (directory, uid) = source_directory();
        let bundle = bundle();
        let mut engine = CacheBootstrapImportEngineV1::default();
        engine.decode_requested(&bundle).unwrap();
        engine.opening = Some(Ok(open(directory.path(), uid)));
        engine.import_opened::<true>(&bundle).unwrap();
        fs::rename(
            directory.path().join("source.journal"),
            directory.path().join("moved.journal"),
        ).unwrap();

        assert!(engine.initial_source_post().is_err());

        assert!(matches!(engine.first, Some(ImportFailure::SourcePost)));
        assert!(matches!(engine.source_post, Some(Err(_))));
        assert!(matches!(engine.native, Some(Ok(_))));
        assert!(engine.opening.as_ref().unwrap().is_ok());
        assert!(engine.failure().is_some());
        assert!(engine.final_opening.is_none());
    }
}
