//! Retains one complete native name/prefix/index observation and its partials.

use super::*;

pub(super) struct ReadObservation {
    names: WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
    names_result: Option<Result<(), NativeJournalDataErrorV1>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    replay: CanonicalReplayOriginalV1,
    replay_result: Option<Result<(), NativeJournalDataErrorV1>>,
    comparison: Option<Result<(), NativeJournalDataErrorV1>>,
    replay_attempted: bool,
    completed: bool,
    disposed: bool,
}

impl ReadObservation {
    pub(super) fn new() -> Self {
        Self {
            names: WriterCurrentnessOriginalsV1::new(),
            names_result: None,
            metadata: None,
            replay: CanonicalReplayOriginalV1::new(),
            replay_result: None,
            comparison: None,
            replay_attempted: false,
            completed: false,
            disposed: false,
        }
    }

    pub(super) fn prepare_once<P>(
        &mut self,
        native: &NativeJournal<RecordNamespace, JournalLimits>,
        location: &ProtectedJournalLocation<P>,
    ) {
        if self.names_result.is_some() {
            return;
        }
        self.names_result = Some(self.observe_names(native, location));
        if !matches!(self.names_result, Some(Ok(()))) {
            return;
        }
        self.metadata = Some(native.file().metadata());
    }

    pub(super) fn captured_end(&self) -> Option<u64> {
        self.metadata.as_ref()?.as_ref().ok().map(std::fs::Metadata::len)
    }

    pub(super) fn replay_was_attempted(&self) -> bool {
        self.replay_attempted
    }

    pub(super) fn replay_once(
        &mut self,
        native: &NativeJournal<RecordNamespace, JournalLimits>,
        idempotency: &BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
        expected_end: u64,
    ) {
        if self.replay_attempted {
            return;
        }
        self.replay_attempted = true;
        if self.captured_end() != Some(expected_end)
            || !matches!(self.names_result, Some(Ok(())))
        {
            self.comparison = Some(Err(NativeJournalDataErrorV1::ProtectedBoundary));
            return;
        }
        let Some(Ok(metadata)) = self.metadata.as_ref() else {
            return;
        };
        self.replay_result = Some(self.replay.capture_prefix_once(
            native.file(), native.limits(), metadata.len(),
        ));
        if !matches!(self.replay_result, Some(Ok(()))) {
            return;
        }
        self.comparison = Some((|| {
            let (durable_end, _) = self.replay.report()
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
            if native.is_poisoned() || !self.replay.matches_native(native)
                || durable_end != expected_end
            {
                return Err(NativeJournalDataErrorV1::ProtectedBoundary);
            }
            require_native_index(native, idempotency)
        })());
        self.completed = matches!(self.comparison, Some(Ok(())));
    }

    fn observe_names<P>(
        &mut self,
        native: &NativeJournal<RecordNamespace, JournalLimits>,
        location: &ProtectedJournalLocation<P>,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.names.begin(false)?;
        let result = (|| {
            if native.is_poisoned()
                || native.path().file_name().is_none_or(|name| name != location.name())
            {
                return Err(NativeJournalDataErrorV1::ProtectedBoundary);
            }
            let root = native.path().parent()
                .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
            self.names.observe_directory(root, location.expected_uid())?;
            self.names.bind_location(location)?;
            self.names.observe_names(
                location, location.name(), location.expected_uid(), native.lock_file(), native.file(),
            )
        })();
        self.names.finish(result)
    }

    #[cfg(test)]
    pub(super) fn retained_file_count(&self) -> usize {
        self.names.retained_file_count()
    }

    #[cfg(test)]
    pub(super) fn is_disposed(&self) -> bool {
        self.disposed
    }

    pub(super) fn is_complete(&self) -> bool {
        self.completed && self.failure().is_none()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.names.failure()
            .or_else(|| error(&self.names_result))
            .or_else(|| error(&self.metadata))
            .or_else(|| self.replay.failure())
            .or_else(|| error(&self.replay_result))
            .or_else(|| error(&self.comparison))
    }

    pub(super) fn dispose_positive_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.disposed || !self.is_complete() {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.names.settle_positive_once_v1();
        // Full native/index comparison and the enclosing independent native
        // post have completed. No next operation is admitted by this cleanup.
        // Replace the actual owner so every Vec/BTree backing really drops.
        self.replay = CanonicalReplayOriginalV1::new();
        self.disposed = true;
        Ok(())
    }
}

fn error<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}
