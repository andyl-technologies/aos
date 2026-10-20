//! Retains the actual common readonly opener beside its full role semantics.
//!
//! Native custody and canonical replay stay in the common owner. This wrapper
//! keeps the genuine Root/Cache receiving contexts, independent name posts,
//! typed semantic failures and guarded readonly materialization together.

use super::*;
use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryHeldJournalV1, CanonicalOrdinaryReadonlyOpeningV1, NativeJournalDataErrorV1,
};

type Native = CanonicalOrdinaryReadonlyOpeningV1<JournalError>;
type Held = CanonicalOrdinaryHeldJournalV1<
    crate::journal::native_backing::Selection,
    JournalAuthorityInstance,
>;
type Semantic = crate::journal::ordinary_semantics::OrdinarySemanticReplayOriginalV1;
type Remainder = crate::journal::semantic_remainder::DomainSemanticRemainderDataV1;

/// Keeps actual partial readonly originals without creating funding or authority.
pub(crate) struct ReadOnlyJournalOpenOriginalsV1 {
    pub(in crate::journal) native: Native,
    semantic: Option<Semantic>,
    remainder: Option<Remainder>,
    opened: Option<(Held, aos_sandbox_broker::canonical_journal::RecoveryReport)>,
    replay_result: Option<Result<(), JournalError>>,
    #[cfg(target_os = "linux")]
    pub(super) extent:
        Option<Result<crate::journal::ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    selection: Option<crate::journal::native_backing::Selection>,
    pub(in crate::journal) returned: Option<Result<RecoveryReport, JournalError>>,
    pub(in crate::journal) readback: Option<ReadOnlyProtectedJournal>,
    witness: Option<ReadOnlyJournalNameWitness>,
    pub(super) initial_name: Option<Result<(), JournalError>>,
    post_name: Option<Result<(), JournalError>>,
    pub(in crate::journal) attempted: bool,
    post_attempted: bool,
    pub(super) closed: bool,
    pub(super) captured: captured_readonly::CapturedReadOnlyPreparationV1,
    pub(super) named_receiving: Option<super::super::super::readonly_names::ReadonlyNameArchiveV1>,
}

impl ReadOnlyJournalOpenOriginalsV1 {
    /// Constructs only inert destinations; semantic construction follows payment.
    pub(crate) const fn new() -> Self {
        Self {
            native: Native::new(),
            semantic: None,
            remainder: None,
            opened: None,
            replay_result: None,
            #[cfg(target_os = "linux")]
            extent: None,
            selection: None,
            returned: None,
            readback: None,
            witness: None,
            initial_name: None,
            post_name: None,
            attempted: false,
            post_attempted: false,
            closed: false,
            captured: captured_readonly::CapturedReadOnlyPreparationV1::new(),
            named_receiving: None,
        }
    }

    pub(crate) fn open_once(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        directory_identity: (u64, u64),
    ) {
        if self.attempted || self.closed {
            self.closed = true;
            return;
        }
        self.attempted = true;
        self.returned = Some(self.open_inner(path, name, limits, uid, directory_identity));
        self.initial_name = self.observe_names();
    }

    pub(in crate::journal) fn open_inner(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        expected_directory: (u64, u64),
    ) -> Result<RecoveryReport, JournalError> {
        self.prepare_native_inner(path, name, limits, uid, expected_directory, None)?;
        self.finish_read_only_inner(
            limits,
            false,
            #[cfg(target_os = "linux")]
            None,
        )
    }

    pub(super) fn prepare_native_inner(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        expected_directory: (u64, u64),
        retained_lock_name: Option<&mut Option<String>>,
    ) -> Result<(), JournalError> {
        self.native
            .prepare_bound_directory_once_v1(path, name, limits, uid, expected_directory)?;
        validate_limits(limits)?;
        self.native
            .prepare_bound_files_once_v1(retained_lock_name)?;
        let (directory, file, lock) = self
            .native
            .identities_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        #[cfg(target_os = "linux")]
        let selection =
            runtime_deployment_history::OriginalCompactionSelectionV1::capture(path, name);
        #[cfg(not(target_os = "linux"))]
        let selection = ();
        self.selection = Some(selection);
        self.witness = Some(ReadOnlyJournalNameWitness {
            physical: aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness::from_original_parts((
                path.to_owned(), name.to_owned(), uid, directory, file, lock,
            )),
        });
        Ok(())
    }

    fn observe_prefix_length_once(&mut self, limits: JournalLimits) -> Result<u64, JournalError> {
        let length = match self.native.captured_length_data_v1() {
            Some(length) => length,
            None => self.native.capture_metadata_once_v1()?,
        };
        if length > limits.maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }
        Ok(length)
    }

    pub(super) fn capture_prefix_once(
        &mut self,
        limits: JournalLimits,
    ) -> Result<u64, JournalError> {
        let length = self.observe_prefix_length_once(limits)?;
        #[cfg(target_os = "linux")]
        {
            if self.extent.is_none() {
                self.extent = Some(
                    crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                        limits, length,
                    ),
                );
            }
            if !matches!(self.extent, Some(Ok(_))) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(length)
    }

    pub(super) fn finish_read_only_inner(
        &mut self,
        limits: JournalLimits,
        captured: bool,
        #[cfg(target_os = "linux")] receiving: Option<
            crate::journal::ReadonlyReceivingContextV1<'_, '_, '_, '_>,
        >,
    ) -> Result<RecoveryReport, JournalError> {
        #[cfg(target_os = "linux")]
        if receiving.is_some() && !captured {
            return Err(JournalError::ProtectedBoundary);
        }
        let length = if captured {
            self.capture_prefix_once(limits)?
        } else {
            self.observe_prefix_length_once(limits)?
        };
        self.replay_result = Some((|| {
            #[cfg(target_os = "linux")]
            let mut receiving = match receiving {
                Some(receiving) => Some(receiving.bind_captured_file_end(length)?),
                None => None,
            };
            self.semantic = Some(Semantic::new());
            let (identity, mut cursor) = if captured {
                self.native.begin_retained_captured_replay_once_v1()
            } else {
                self.native.begin_retained_original_replay_once_v1()
            }
            .map_err(project_native)?;
            let semantic = self
                .semantic
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            #[cfg(target_os = "linux")]
            semantic
                .observe_captured_readonly_once(&mut cursor, identity, limits, receiving.as_mut())
                .map_err(|()| JournalError::ProtectedBoundary)?;
            #[cfg(not(target_os = "linux"))]
            semantic
                .observe_once(&mut cursor, identity, limits, None)
                .map_err(|()| JournalError::ProtectedBoundary)?;
            Ok(())
        })());
        // This actual post is owed after entry even when context/parser/semantic
        // work failed. Consult the first replay Result only after it is parked.
        if captured {
            self.native.observe_retained_prefix_post_once_v1();
        }
        if !matches!(self.replay_result, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        if captured
            && self
                .native
                .retained_prefix_post_v1()
                .is_none_or(|post| post.failure().is_some())
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let truncated_bytes = self.native.finish_retained_tail_once_v1()?;
        self.remainder = self
            .semantic
            .as_mut()
            .and_then(Semantic::take_remainder_once);
        self.remainder
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.witness
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let selection = self
            .selection
            .take()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.opened = self
            .native
            .take_held_with_late_payload_once_v1(selection, JournalAuthorityInstance);
        let witness = self.witness.take().ok_or(JournalError::ProtectedBoundary)?;
        #[cfg(target_os = "linux")]
        let mut captured_append = None;
        let materialized = Journal::from_actual_ordinary_held_v1(
            &mut self.opened,
            &mut self.remainder,
            #[cfg(target_os = "linux")]
            &mut captured_append,
        );
        match materialized {
            Some((journal, mut report)) => {
                report.truncated_bytes = truncated_bytes;
                self.readback = Some(ReadOnlyProtectedJournal {
                    journal,
                    witness,
                    named_receiving: self.named_receiving.take(),
                });
                Ok(report)
            }
            None => {
                self.witness = Some(witness);
                Err(JournalError::ProtectedBoundary)
            }
        }
    }

    pub(crate) fn recheck_named_once(&mut self) {
        if self.post_attempted || !self.attempted {
            self.closed = true;
            return;
        }
        self.post_attempted = true;
        self.post_name = self.observe_names();
    }

    pub(in crate::journal) fn observe_names(&self) -> Option<Result<(), JournalError>> {
        if let Some(readback) = &self.readback {
            return Some(readback.check_named_currentness());
        }
        let witness = self.witness.as_ref()?;
        if !self.native.has_native_file_data_v1() {
            return None;
        }
        Some(match &self.named_receiving {
            Some(archive) => archive.observe_opening_v1(witness, &self.native),
            None => self
                .native
                .require_temporary_names_current_v1::<JournalError>(&witness.physical),
        })
    }

    pub(crate) fn observe_named_currentness(&self) -> Option<Result<(), JournalError>> {
        self.observe_names()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure_inner(true)
    }

    pub(crate) fn root_controller_primary_failure_v1(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure_inner(false)
    }

    fn failure_inner(&self, include_post: bool) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = self
            .native
            .acquisition_failure_v1()
            .or_else(|| {
                #[cfg(target_os = "linux")]
                {
                    self.extent.as_ref()?.as_ref().err().map(|cause| cause as _)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    None
                }
            })
            .or_else(|| self.semantic.as_ref()?.source_failure_cause_v1())
            .or_else(|| self.native.retained_parser_preparation_failure_v1())
            .or_else(|| {
                let cause = self.native.replay_failure_v1()?;
                // The canonical cursor owns the native wrapper. Preserve the
                // original role diagnostic's typed frame borrow, without
                // moving that wrapper or replacing its independently owed post.
                match cause.downcast_ref::<NativeJournalDataErrorV1>() {
                    Some(NativeJournalDataErrorV1::Frame(frame)) => Some(frame as _),
                    _ => Some(cause),
                }
            })
            .or_else(|| self.native.index_failure_v1())
            .or_else(|| self.semantic.as_ref()?.failure())
            .or_else(|| {
                self.replay_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.native.retained_prefix_post_v1()?.failure())
            .or_else(|| self.native.retained_tail_failure_v1())
            .or_else(|| self.captured.failure())
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.initial_name
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                if include_post {
                    self.post_name
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                } else {
                    None
                }
            })
            .or_else(|| self.native.order_failure_v1())
            .or_else(|| {
                self.closed
                    .then_some(&READ_ONLY_OPEN_CLOSED as &(dyn std::error::Error + 'static))
            })?;
        match cause.downcast_ref::<JournalError>() {
            Some(JournalError::ReadOnlyNameReceivingFailure(index)) => self
                .named_receiving_failure(*index)
                .map(|cause| cause as _)
                .or(Some(cause)),
            _ => Some(cause),
        }
    }

    pub(crate) fn named_receiving_failure(&self, index: u8) -> Option<&JournalError> {
        match &self.readback {
            Some(readback) => readback.named_receiving_failure(index),
            None => self.named_receiving.as_ref()?.failure_at(index),
        }
    }

    // The surrounding Root state or Runtime worker already pays its inline
    // resident owner. This complete helper bound covers actual constructor,
    // parser/semantic loans, conversion/return and late-marker work planes.
    // Source family backing stays at the existing genuine semantic frontier.
    fn receiving_construction_demand_v1() -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        use aos_sandbox_broker::canonical_journal::CanonicalJournalInstanceDataV1;
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let invalid = || JournalError::LimitExceeded("retained readonly construction");
        let bytes = Native::receiving_construction_bytes_v1::<
            crate::journal::native_backing::Selection, JournalAuthorityInstance,
        >().ok_or_else(invalid)?
            .checked_add(Semantic::readonly_receiving_construction_bytes_v1()?)
            .and_then(|bytes| bytes.checked_add(Journal::ordinary_materialization_receiving_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(
                CanonicalJournalInstanceDataV1::<JournalAuthorityInstance>::payload_allocation_receiving_bytes_v1()?,
            ))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ResourceVector>().checked_mul(4)?))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?))
    }

    /// Bounds the same native base plus readonly-only construction before entry.
    pub(crate) fn fixed_preparation_demand_v1<T>(
        directory_descriptors: u16,
        path_name_bytes: u16,
    ) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        let native = ProtectedWriterOpenOriginalsV1::fixed_preparation_demand_v1::<T>(
            directory_descriptors,
            path_name_bytes,
        )?;
        native
            .checked_add(Self::receiving_construction_demand_v1()?)
            .map_err(Into::into)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn cache_named_receiving_demand_v1()
    -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        // Cache's actual fixed native suppliers above include construction.
        super::super::super::readonly_names::ReadonlyNameArchiveV1::cache_demand()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn root_controller_named_receiving_demand_v1()
    -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        // Root's outer state prices resident fields; this is its actual fixed
        // named-preparation gate for additional native/semantic work planes.
        super::super::super::readonly_names::ReadonlyNameArchiveV1::root_controller_demand()?
            .checked_add(Self::receiving_construction_demand_v1()?)
            .map_err(Into::into)
    }

    pub(crate) fn readback_mut(&mut self) -> Option<&mut ReadOnlyProtectedJournal> {
        if self.closed
            || self.failure().is_some()
            || !matches!(self.returned, Some(Ok(_)))
            || !matches!(self.initial_name, Some(Ok(())))
        {
            return None;
        }
        self.readback.as_mut()
    }
}

fn project_native(
    cause: aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1,
) -> JournalError {
    crate::journal::CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause).into()
}
