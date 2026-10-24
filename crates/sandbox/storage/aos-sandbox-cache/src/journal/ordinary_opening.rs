//! Opens the five fixed Cache ordinary roles through one native engine.
//!
//! These existing operation intervals use ordinary allocation. The initial
//! five captured constructors remain separate and retain their real financial
//! loans. Production directories/names select only those same compiled roles;
//! no state map, file or completed replay can be adopted here.

use std::path::Path;

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryOpeningOriginalsV1, NativeJournalDataErrorV1,
    coordinator::indexed_replay::CanonicalIndexedReplayErrorV1,
};
use aos_sandbox_journal::recovery::RecoveryTailMode;
use aos_sandbox_ledger_replay::cold::ColdReplayOriginalV1;
use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1;

use super::{CacheCompactionSelectionV1, CacheJournalInstanceV1, Journal, JournalError};

// Existing-only versus creating intervals retain their original torn-tail
// policy. This private selection grants no financial or Cache role authority.
pub(crate) enum CacheOrdinaryOpenV1 {
    Creating,
    Existing,
}

// Synthetic fixture identities remain distinct from production Cache roles.
// Only these existing tests can select these five names; acquisition and full
// Cold replay still run through the same native engine below.
#[cfg(test)]
pub(crate) enum CacheOrdinaryFixtureV1 {
    RootWriter,
    GeometrySource,
    GeometryAuthority,
    GeometryState,
    ImportSource,
}

#[cfg(test)]
impl CacheOrdinaryFixtureV1 {
    fn basename_v1(self) -> &'static str {
        match self {
            Self::RootWriter => "root.journal",
            Self::GeometrySource => "geometry-source.journal",
            Self::GeometryAuthority => "geometry-authority.journal",
            Self::GeometryState => "geometry-state.journal",
            Self::ImportSource => "source.journal",
        }
    }
}

fn native_error(cause: NativeJournalDataErrorV1) -> JournalError {
    JournalError::from_ordinary_native_v1(cause)
}

fn indexed_error(cause: CanonicalIndexedReplayErrorV1) -> JournalError {
    match cause {
        CanonicalIndexedReplayErrorV1::Native(cause) => native_error(cause),
        CanonicalIndexedReplayErrorV1::Closed => JournalError::boundary(),
    }
}

impl Journal {
    pub(super) fn open_cache_hold_ordinary_v1(
        directory: &Path,
        uid: u32,
    ) -> Result<Self, JournalError> {
        Self::open_cache_hold_v1(directory, uid, CacheOrdinaryOpenV1::Creating)
    }

    pub(super) fn open_existing_cache_hold_ordinary_v1(
        directory: &Path,
        uid: u32,
    ) -> Result<Self, JournalError> {
        Self::open_cache_hold_v1(directory, uid, CacheOrdinaryOpenV1::Existing)
    }

    fn open_cache_hold_v1(
        directory: &Path,
        uid: u32,
        disposition: CacheOrdinaryOpenV1,
    ) -> Result<Self, JournalError> {
        let role = CacheJournalRecipeRoleV1::Hold;
        Self::open_fixed_ordinary_v1(
            directory,
            uid,
            role.basename_v1(),
            role.limits_v1(),
            disposition,
        )
        .map(|(journal, _)| journal)
    }

    #[cfg(test)]
    pub(super) fn open_gate_target_fixture_v1(
        directory: &Path,
        uid: u32,
        role: CacheJournalRecipeRoleV1,
        limits: super::JournalLimits,
    ) -> Result<Self, JournalError> {
        if !matches!(role, CacheJournalRecipeRoleV1::State | CacheJournalRecipeRoleV1::Authority) {
            return Err(JournalError::boundary());
        }
        Self::open_fixed_ordinary_v1(
            directory,
            uid,
            role.basename_v1(),
            limits,
            CacheOrdinaryOpenV1::Creating,
        )
        .map(|(journal, _)| journal)
    }

    /// Opens exactly one of Cache's five canonical ordinary writer roles.
    ///
    /// The old ordinary allocation policy remains distinct from selected paid
    /// construction. Native bounds, full Cold replay and recovery disposition
    /// use the same engine below; no file, state map or native bundle is adopted.
    ///
    /// # Errors
    /// Rejects a foreign role/root or any unchanged native/replay/bounds failure.
    pub(crate) fn open_cache_ordinary_role_v1(
        directory: &Path,
        name: &str,
        limits: super::JournalLimits,
        uid: u32,
        disposition: CacheOrdinaryOpenV1,
    ) -> Result<(Self, super::RecoveryReport), JournalError> {
        let role = [
            CacheJournalRecipeRoleV1::Bootstrap,
            CacheJournalRecipeRoleV1::Hold,
            CacheJournalRecipeRoleV1::State,
            CacheJournalRecipeRoleV1::Authority,
            CacheJournalRecipeRoleV1::Clock,
        ].into_iter().find(|role| role.basename_v1() == name)
            .ok_or(JournalError::boundary())?;
        #[cfg(not(test))]
        if directory != Path::new(role.writer_directory_v1()) {
            return Err(JournalError::boundary());
        }
        Self::open_fixed_ordinary_v1(directory, uid, role.basename_v1(), limits, disposition)
    }

    /// Opens one of the existing synthetic test journals with real native custody.
    ///
    /// # Errors
    /// Returns the unchanged native opening, replay, bounds or transfer failure.
    #[cfg(test)]
    pub(crate) fn open_cache_ordinary_fixture_v1(
        directory: &Path,
        fixture: CacheOrdinaryFixtureV1,
        limits: super::JournalLimits,
        uid: u32,
    ) -> Result<(Self, super::RecoveryReport), JournalError> {
        Self::open_fixed_ordinary_v1(
            directory,
            uid,
            fixture.basename_v1(),
            limits,
            CacheOrdinaryOpenV1::Creating,
        )
    }

    fn open_fixed_ordinary_v1(
        directory: &Path,
        uid: u32,
        name: &str,
        limits: super::JournalLimits,
        disposition: CacheOrdinaryOpenV1,
    ) -> Result<(Self, super::RecoveryReport), JournalError> {
        let allow_create = matches!(disposition, CacheOrdinaryOpenV1::Creating);
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        let mut semantic = ColdReplayOriginalV1::new();
        let mut converted = None;
        #[cfg(not(test))]
        let prepared = opening.prepare_ordinary_once_v1(
            directory, name, limits, uid, allow_create,
        );
        #[cfg(test)]
        let prepared = opening.prepare_fixture_ordinary_once_v1(
            directory, name, limits, uid, allow_create,
        );
        let replayed = (|| {
            prepared.map_err(native_error)?;
            let identity = opening.prepare_parser_identity_once_v1().map_err(native_error)?;
            let mut cursor = opening.begin_indexed_replay_once_v1().map_err(native_error)?;
            semantic.observe_ordinary_indexed_once(&mut cursor, identity, limits)
                .map_err(|_| JournalError::boundary())?;
            converted = Some(semantic.take_remainder_once().ok_or(JournalError::boundary())?);
            Ok(())
        })();
        if let Err(body) = replayed {
            let native_selected = opening.native_failure_v1().is_some()
                || opening.index_failure_v1().is_some();
            semantic.dispose_ordinary_prospective_v1();
            let current_disposal = opening.dispose_ordinary_current_once_v1();
            let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
            let pending_disposal = opening.dispose_ordinary_pending_once_v1();
            let errors = opening.into_ordinary_errors_v1();
            if let Ok((index, native)) = errors {
                if native_selected {
                    if let Some(cause) = index {
                        return Err(cause.into());
                    }
                    if let Some(cause) = native {
                        return Err(native_error(cause));
                    }
                }
            }
            if let Some(cause) = upper_native {
                return Err(indexed_error(cause));
            }
            if let Some(cause) = upper_semantic {
                return Err(cause.into());
            }
            drop(current_disposal);
            drop(pending_disposal);
            return Err(body);
        }

        semantic.dispose_ordinary_prospective_v1();
        opening.dispose_ordinary_current_once_v1().map_err(native_error)?;
        drop(semantic.into_ordinary_errors());
        opening.dispose_ordinary_pending_once_v1().map_err(native_error)?;
        let tail = if allow_create {
            RecoveryTailMode::RepairIncomplete
        } else {
            RecoveryTailMode::RejectIncomplete
        };
        if let Err(projected) = opening.finish_replayed_tail_once_v1(tail) {
            drop(converted.take());
            return Err(Self::ordinary_hold_disposed_error_v1(opening, native_error(projected)));
        }

        let mut native = match opening.take_held_with_late_payload_once_v1(
            CacheCompactionSelectionV1::Other, CacheJournalInstanceV1,
        ) {
            Some(native) => Some(native),
            None => {
                drop(converted.take());
                return Err(Self::ordinary_hold_disposed_error_v1(opening, JournalError::boundary()));
            }
        };
        Self::from_opening_originals_v1(&mut native, &mut converted)
            .ok_or(JournalError::boundary())
    }

    fn ordinary_hold_disposed_error_v1(
        opening: CanonicalOrdinaryOpeningOriginalsV1,
        fallback: JournalError,
    ) -> JournalError {
        match opening.into_ordinary_errors_v1() {
            Ok((Some(index), _)) => index.into(),
            Ok((None, Some(native))) => native_error(native),
            Ok((None, None)) => fallback,
            Err(original) => {
                drop(original);
                fallback
            }
        }
    }
}
