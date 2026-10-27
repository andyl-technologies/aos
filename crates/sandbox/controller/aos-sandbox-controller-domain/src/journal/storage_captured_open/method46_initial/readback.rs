//! Retains native bookends around a borrowed original main-map readback.
//!
//! The opening's two full fixed allowances already pay all six potentially
//! retained traversals: acquisition, replay before/after, readback before/after
//! and final names. The body separately pays these inline result owners.

use super::*;

pub(super) struct MainMapReadbackOriginalV1 {
    entered: bool,
    results: [Option<Result<(), JournalError>>; 2],
    originals: [super::super::super::ProtectedJournalCurrentnessOriginalsV1; 2],
}

impl MainMapReadbackOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            entered: false,
            results: [None, None],
            originals: [
                super::super::super::ProtectedJournalCurrentnessOriginalsV1::new(),
                super::super::super::ProtectedJournalCurrentnessOriginalsV1::new(),
            ],
        }
    }

    fn sample_failure(&self, index: usize) -> Option<&(dyn Error + 'static)> {
        self.originals[index].failure().or_else(|| {
            self.results[index]
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as _)
        })
    }

    pub(super) fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.sample_failure(0)
    }

    pub(super) fn after_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.sample_failure(1)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_failure().or_else(|| self.after_failure())
    }
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn readback_available_data(&self) -> bool {
        !self.readback.entered
            && self.post.is_none()
            && self.failure().is_none()
            && matches!(self.nonempty, Some(Ok(())))
            && self.inner.replay_ready()
            && self.namespace_admitted()
    }

    fn observe_readback(&mut self, round: usize) -> Result<(), JournalError> {
        self.readback.results[round] = Some((|| {
            self.inner.original.check_named_currentness_retaining(
                self.inner
                    .recipe
                    .directory()
                    .ok_or(JournalError::ProtectedBoundary)?,
                self.inner.recipe.name(),
                self.inner.limits.ok_or(JournalError::ProtectedBoundary)?,
                self.inner
                    .recipe
                    .uid()
                    .ok_or(JournalError::ProtectedBoundary)?,
                &mut self.readback.originals[round],
            )
        })());
        self.readback.originals[round].settle_positive_once_v1();
        if matches!(self.readback.results[round], Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn begin_readback_once(&mut self) -> Result<(), JournalError> {
        if self.readback.entered
            || self.post.is_some()
            || self.failure().is_some()
            || !matches!(self.nonempty, Some(Ok(())))
            || !self.inner.replay_ready()
            || !self.namespace_admitted()
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.readback.entered = true;
        self.observe_readback(0)?;
        self.observe_approval_before_once()
    }

    pub(crate) fn readback_journal_data(&self) -> Option<&Journal> {
        if self.failure().is_some()
            || !self.readback.entered
            || !matches!(self.readback.results[0], Some(Ok(())))
            || self.readback.results[1].is_some()
            || self.post.is_some()
        {
            return None;
        }
        self.inner.original.journal_data_v1()
    }

    pub(crate) fn finish_readback_after_owed(&mut self) -> Result<(), JournalError> {
        if !self.readback.entered {
            return Ok(());
        }
        if self.readback.results[1].is_none() {
            self.observe_readback(1)?;
        }
        if self.readback.failure().is_none()
            && matches!(self.readback.results, [Some(Ok(())), Some(Ok(()))])
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }
}
