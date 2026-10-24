//! Holds each fixed catalog opening and the separate ordinary worker adapter.
//!
//! All parser, indexed replay, tail and captured append stages come from the
//! existing shared mechanics. Network checks its closed key schema at each
//! logical COMMIT; typed catalogs retain their later MAC/transition validation.

use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::canonical_journal::network_opening::NetworkCapturedJournalOpeningOriginalV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1 as MechanicalCause, CanonicalOrdinaryOpeningOriginalsV1,
    NativeJournalDataErrorV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::ProtectedFailure;
use aos_sandbox_journal::recovery::RecoveryTailMode;

use super::replay::NetworkReplayOriginalV1;
use super::*;

struct FixedOpening {
    native: NetworkCapturedJournalOpeningOriginalV1,
    replay: NetworkReplayOriginalV1,
    extent: Option<ProtectedJournalPreopenReplayExtentV1>,
    limits: Option<JournalLimits>,
    schema: Schema,
    native_result: Option<Result<(), NativeJournalDataErrorV1>>,
    body: Option<Result<(), JournalError>>,
    native_selected: bool,
    entered: bool,
    reentry: Option<JournalError>,
}

impl FixedOpening {
    const fn new(native: NetworkCapturedJournalOpeningOriginalV1, schema: Schema) -> Self {
        Self {
            native,
            replay: NetworkReplayOriginalV1::new(),
            extent: None,
            limits: None,
            schema,
            native_result: None,
            body: None,
            native_selected: false,
            entered: false,
            reentry: None,
        }
    }

    fn fixed_demand(native: ResourceVector) -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Journal>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        native
            .checked_add(
                CapturedAppendDataOwnerV1::<JournalError>::construction_demand_v1()
                    .ok_or(JournalError::JournalTooLarge)?,
            )?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(Into::into)
    }

    fn prepare_once(&mut self, limits: JournalLimits) {
        if self.limits.is_some() {
            self.reentry.get_or_insert(JournalError::BOUNDARY);
            return;
        }
        self.limits = Some(limits);
        self.native.prepare_once(limits, true);
        if let Some(extent) = self.native.captured_extent().copied() {
            match ProtectedJournalPreopenReplayExtentV1::from_canonical(extent, self.schema) {
                Ok(extent) => self.extent = Some(extent),
                Err(cause) => self.body = Some(Err(cause)),
            }
        }
    }

    fn replay_once(&mut self) {
        if self.entered || self.body.is_some() {
            self.reentry.get_or_insert(JournalError::BOUNDARY);
            return;
        }
        self.entered = true;
        self.body = Some((|| {
            let limits = self.limits.ok_or(JournalError::BOUNDARY)?;
            let outcome = match self.native.begin_replay_once() {
                Ok((_identity, mut cursor)) => {
                    self.replay.observe_once(&mut cursor, self.schema, limits)
                }
                Err(cause) => {
                    self.native_result = Some(Err(cause));
                    Err(())
                }
            };
            self.native_selected = self.native.failure().is_some();
            outcome.map_err(|_| JournalError::BOUNDARY)?;
            self.native_result = Some(self.native.finish_tail_once());
            self.native_selected = self.native.failure().is_some();
            if !matches!(self.native_result, Some(Ok(()))) {
                return Err(JournalError::BOUNDARY);
            }
            Ok(())
        })());
        self.native.observe_after_owed_once();
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.native_selected {
            return self.native.failure().or_else(|| self.replay.failure());
        }
        self.replay
            .failure()
            .or_else(|| {
                self.native_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
            .or_else(|| self.native.failure())
    }

    fn take_opened(&mut self) -> Option<(Journal, RecoveryReport)> {
        if !matches!(self.body, Some(Ok(())))
            || !self.replay.is_complete()
            || self.failure().is_some()
        {
            return None;
        }
        let captured = self.native.append_binding_data_v1();
        let (held, report) = self
            .native
            .take_held_once_v1(NetworkCompactionSelectionV1::Other)?;
        Some((
            Journal::from_held(held, self.schema, Some(captured)),
            report,
        ))
    }

    fn require_same(&self, journal: &Journal) -> Result<(), JournalError> {
        if journal
            .identity
            .as_ref()
            .is_some_and(|identity| self.native.matches_writer_data_v1(identity))
        {
            Ok(())
        } else {
            Err(JournalError::BOUNDARY)
        }
    }

    fn inventory_demand(&self) -> Result<ResourceVector, JournalError> {
        let (directory, name, _) = self.native.append_binding_data_v1();
        let one = WriterCurrentnessOriginalsV1::<JournalError>::fixed_demand_v1(
            Path::new(directory),
            name,
        )?;
        let bytes = std::mem::size_of::<FixedServiceInventoryJournalCurrentnessOriginalV2>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        one.checked_add(one)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(Into::into)
    }

    fn inventory_before(
        &self,
        journal: &Journal,
        original: &mut FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> Result<(), JournalError> {
        if original.before_result.is_some() || original.binding.is_some() {
            return original.reenter();
        }
        let (directory, name, uid) = self.native.append_binding_data_v1();
        original.binding = Some((directory, name, uid));
        original.before_result = Some((|| {
            self.require_same(journal)?;
            if self.failure().is_some() {
                return Err(JournalError::BOUNDARY);
            }
            journal.validate_held_owned_at_for_uid_retaining(
                Path::new(directory),
                name,
                uid,
                &mut original.before,
            )
        })());
        original.finish_result(true)
    }

    fn inventory_after(
        &self,
        journal: &Journal,
        original: &mut FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> Result<(), JournalError> {
        if original.before_result.is_none() || original.after_result.is_some() {
            return original.reenter();
        }
        original.after_result = Some((|| {
            // Native after is still owed after an unhealthy primary. Only the
            // actual same writer/recipe association gates these observations.
            self.require_same(journal)?;
            let (directory, name, uid) = self.native.append_binding_data_v1();
            if original.binding != Some((directory, name, uid)) {
                return Err(JournalError::BOUNDARY);
            }
            original.after.begin(false)?;
            let view = journal.read_view();
            let directory =
                view.observe_directory_binding_into(Path::new(directory), uid, &mut original.after);
            let names = view.observe_names_into(&mut original.after);
            original.after.finish(directory.and(names))
        })());
        original.finish_result(false)
    }
}

#[derive(Clone, Copy)]
enum InventoryFirst {
    Before,
    After,
    Reentry,
}

/// Retains both original native observations of one private fixed writer.
pub(crate) struct FixedServiceInventoryJournalCurrentnessOriginalV2 {
    binding: Option<(&'static str, &'static str, u32)>,
    before: WriterCurrentnessOriginalsV1<JournalError>,
    after: WriterCurrentnessOriginalsV1<JournalError>,
    before_result: Option<Result<(), JournalError>>,
    after_result: Option<Result<(), JournalError>>,
    reentry: Option<JournalError>,
    first: Option<InventoryFirst>,
}

impl Default for FixedServiceInventoryJournalCurrentnessOriginalV2 {
    fn default() -> Self {
        Self {
            binding: None,
            before: WriterCurrentnessOriginalsV1::new(),
            after: WriterCurrentnessOriginalsV1::new(),
            before_result: None,
            after_result: None,
            reentry: None,
            first: None,
        }
    }
}

impl FixedServiceInventoryJournalCurrentnessOriginalV2 {
    fn reenter(&mut self) -> Result<(), JournalError> {
        self.reentry.get_or_insert(JournalError::BOUNDARY);
        self.first.get_or_insert(InventoryFirst::Reentry);
        Err(JournalError::BOUNDARY)
    }

    fn finish_result(&mut self, before: bool) -> Result<(), JournalError> {
        if matches!(
            if before {
                &self.before_result
            } else {
                &self.after_result
            },
            Some(Ok(()))
        ) {
            Ok(())
        } else {
            self.first.get_or_insert(if before {
                InventoryFirst::Before
            } else {
                InventoryFirst::After
            });
            Err(JournalError::BOUNDARY)
        }
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            InventoryFirst::Before => self.before.failure().or_else(|| {
                self.before_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            InventoryFirst::After => self.after.failure().or_else(|| {
                self.after_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            InventoryFirst::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    pub(crate) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if self.first.is_none()
            && matches!(self.before_result, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(JournalError::BOUNDARY)
        }
    }
}

macro_rules! fixed_opening {
    ($name:ident, $native:ident, $quote:ident, $schema:ident) => {
        pub(crate) struct $name(FixedOpening);

        impl $name {
            pub(crate) const fn new() -> Self {
                Self(FixedOpening::new(
                    NetworkCapturedJournalOpeningOriginalV1::$native(),
                    Schema::$schema,
                ))
            }

            pub(crate) fn fixed_preparation_demand() -> Result<ResourceVector, JournalError> {
                FixedOpening::fixed_demand(
                    NetworkCapturedJournalOpeningOriginalV1::$quote()
                        .map_err(JournalError::from)?,
                )
            }

            pub(crate) fn prepare_once(&mut self, limits: JournalLimits) {
                self.0.prepare_once(limits);
            }

            pub(crate) fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
                self.0.extent.as_ref()
            }

            pub(crate) fn replay_once(&mut self) {
                self.0.replay_once();
            }

            pub(crate) fn take_opened(&mut self) -> Option<(Journal, RecoveryReport)> {
                self.0.take_opened()
            }

            pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
                self.0.failure()
            }

            pub(crate) fn inventory_currentness_receiving_demand_v2(
                &self,
            ) -> Result<ResourceVector, JournalError> {
                self.0.inventory_demand()
            }

            pub(crate) fn observe_inventory_currentness_before_v2(
                &self,
                journal: &Journal,
                original: &mut FixedServiceInventoryJournalCurrentnessOriginalV2,
            ) -> Result<(), JournalError> {
                self.0.inventory_before(journal, original)
            }

            pub(crate) fn observe_inventory_currentness_after_owed_v2(
                &self,
                journal: &Journal,
                original: &mut FixedServiceInventoryJournalCurrentnessOriginalV2,
            ) -> Result<(), JournalError> {
                self.0.inventory_after(journal, original)
            }
        }
    };
}

fixed_opening!(
    NetworkCreationCapturedJournalOpenV4,
    creation,
    creation_receiving_demand_v1,
    Creation
);
fixed_opening!(
    NetworkLifecycleCapturedJournalOpenV4,
    lifecycle,
    lifecycle_receiving_demand_v1,
    Lifecycle
);
fixed_opening!(
    NetworkPreparationCapturedJournalOpenV4,
    preparation,
    preparation_receiving_demand_v1,
    Preparation
);
fixed_opening!(
    NetworkNamespaceCapturedJournalOpenV4,
    namespace,
    namespace_receiving_demand_v1,
    Namespace
);
fixed_opening!(
    NetworkWorkerReplayCapturedJournalOpenV4,
    worker,
    worker_receiving_demand_v1,
    Worker
);

impl NetworkWorkerReplayCapturedJournalOpenV4 {
    pub(crate) fn positive_retained_frontier_files_data_v2() -> Option<usize> {
        // The actual successful fixed acquisition retires its ancestors before
        // transfer. Its retained directory, journal and lock are the frontier.
        Some(["directory", "journal", "lock"].len())
    }

    pub(crate) fn maximum_append_receiving_demand_v4(
        limits: JournalLimits,
        encoded: u64,
    ) -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1> {
        super::receiving::maximum_worker_append_demand(limits, encoded)
    }
}

impl Journal {
    pub(crate) fn open_protected_at(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let schema = Schema::from_name(name)?;
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        let mut semantic = NetworkReplayOriginalV1::new();
        let outcome = (|| {
            opening.prepare_ordinary_once_v1(directory, name, limits, 0, true)?;
            let mut cursor = opening.begin_indexed_replay_once_v1()?;
            semantic
                .observe_once(&mut cursor, schema, limits)
                .map_err(|_| JournalError::BOUNDARY)?;
            drop(cursor);
            opening.finish_replayed_tail_once_v1(RecoveryTailMode::RepairIncomplete)?;
            Ok::<_, JournalError>(())
        })();
        if let Err(cause) = outcome {
            // Keep the old lexical frontier: current frame/COMMIT, semantic
            // temporaries, pending/compaction locals, index, then native prefix
            // and physical acquisition. Every step moves its original cause.
            let _ = opening.dispose_ordinary_current_once_v1();
            let semantic_cause = semantic.into_ordinary_error().map(JournalError::from);
            let _ = opening.dispose_ordinary_pending_once_v1();
            return Err(match opening.into_ordinary_errors_v1() {
                Ok((index_cause, native_cause)) => native_cause
                    .map(JournalError::from)
                    .or_else(|| {
                        index_cause.map(MechanicalCause::from).map(JournalError::from)
                    })
                    .or(semantic_cause)
                    .unwrap_or(cause),
                Err(_original) => cause,
            });
        }
        let (held, report) = opening
            .take_held_without_instance_once_v1(NetworkCompactionSelectionV1::Other)
            .ok_or(JournalError::BOUNDARY)?;
        Ok((Self::from_held(held, schema, None), report))
    }
}

#[cfg(test)]
impl Journal {
    // Tests use unprotected temporary files, as before. Production always uses
    // the protected ordinary or fixed capture above; this adapter drives the
    // same canonical cursor and tail engine without a second byte parser.
    pub(crate) fn open(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_test_with_schema(path, limits, Schema::Fixture)
    }

    pub(super) fn open_test_with_schema(
        path: impl AsRef<Path>,
        limits: JournalLimits,
        schema: Schema,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        let mut semantic = NetworkReplayOriginalV1::new();
        let outcome = (|| {
            opening.prepare_unprotected_ordinary_once_v1(path.as_ref(), limits)?;
            let mut cursor = opening.begin_indexed_replay_once_v1()?;
            semantic
                .observe_once(&mut cursor, schema, limits)
                .map_err(|_| JournalError::BOUNDARY)?;
            drop(cursor);
            opening.finish_replayed_tail_once_v1(RecoveryTailMode::RepairIncomplete)?;
            Ok::<_, JournalError>(())
        })();
        if let Err(cause) = outcome {
            let _ = opening.dispose_ordinary_current_once_v1();
            let semantic_cause = semantic.into_ordinary_error().map(JournalError::from);
            let _ = opening.dispose_ordinary_pending_once_v1();
            return Err(match opening.into_ordinary_errors_v1() {
                Ok((index_cause, native_cause)) => native_cause
                    .map(JournalError::from)
                    .or_else(|| {
                        index_cause.map(MechanicalCause::from).map(JournalError::from)
                    })
                    .or(semantic_cause)
                    .unwrap_or(cause),
                Err(_original) => cause,
            });
        }
        let (held, report) = opening
            .take_held_without_instance_once_v1(NetworkCompactionSelectionV1::Other)
            .ok_or(JournalError::BOUNDARY)?;
        Ok((Self::from_held(held, schema, None), report))
    }
}
