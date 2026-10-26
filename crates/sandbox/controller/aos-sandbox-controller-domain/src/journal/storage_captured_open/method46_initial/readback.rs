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

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.originals[0]
            .failure()
            .or_else(|| {
                self.results[0]
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.originals[1].failure())
            .or_else(|| {
                self.results[1]
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
    }
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn readback_available_data(&self) -> bool {
        !self.readback.entered
            && self.post.is_none()
            && self.failure().is_none()
            && matches!(self.nonempty, Some(Ok(())))
            && self.inner.replay_ready()
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
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.readback.entered = true;
        self.observe_readback(0)
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
