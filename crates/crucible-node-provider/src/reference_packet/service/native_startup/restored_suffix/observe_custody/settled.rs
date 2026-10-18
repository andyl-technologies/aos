//! Serializes every actual recurring request partial without reopening its scope.

use super::*;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

impl NativeRestoredSuffixObserveAttempt {
    pub(crate) fn borrowed_settled_history_data(&self) -> impl Serialize + '_ {
        History(self)
    }
}

struct History<'a>(&'a NativeRestoredSuffixObserveAttempt);
impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeRestoredSuffixObserveAttempt {
            ordinal,
            original,
            body,
            terminal,
            stage,
        } = self.0;
        let mut state = serializer.serialize_struct("NativeSuffixHistory", 6)?;
        state.serialize_field("schema", "source-private.native-restored-observe-attempt/1")?;
        state.serialize_field("ordinal", ordinal)?;
        state.serialize_field("original", original)?;
        state.serialize_field("body", body)?;
        state.serialize_field("terminal", terminal)?;
        state.serialize_field(
            "stage",
            &match stage {
                Stage::Receiving => "receiving",
                Stage::Raw => "raw",
                Stage::Typed => "typed",
                Stage::Dispatched => "dispatched",
                Stage::Published => "published",
                Stage::Failed => "failed",
            },
        )?;
        state.end()
    }
}

impl NativeRestoredSuffixObserveAttempt {
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<History<'static>>()
    }
}

impl NativeRestoredSuffixObserveAttempt {
    /// Appends the selected17 emitted field order without resetting aggregate banks.
    ///
    /// # Errors
    /// Refuses finite metadata exhaustion or checked backing-layout overflow.
    pub(crate) fn observe_current_settled17_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        use crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17;

        let Self {
            ordinal,
            original,
            body,
            terminal,
            stage: _,
        } = self;
        observer.observe(ordinal)?;
        observer.observe(original)?;
        if let Some(body) = body {
            body.observe_current(observer)?;
        }
        observer.observe(terminal)
    }
}
