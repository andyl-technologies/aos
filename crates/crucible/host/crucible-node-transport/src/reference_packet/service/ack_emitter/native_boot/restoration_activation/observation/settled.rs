//! Borrows every actual restoration stage field without creating a native permit.

use super::super::settled::StageHistory;
use super::*;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

impl StageHistory for NativeRestorationObservationAttempt {
    fn write_history<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.ensure_origin().map_err(serde::ser::Error::custom)?;
        let NativeRestorationObservationAttempt {
            creator,
            thread,
            original,
            body,
            artifact,
            context,
            terminal,
            received,
            verified,
            dispatched,
            published,
        } = self;
        let mut state = serializer.serialize_struct("NativeRestorationStageHistory", 12)?;
        state.serialize_field(
            "schema",
            "source-private.native-restoration-observation-history/1",
        )?;
        state.serialize_field("creator", creator)?;
        let _ = thread;
        state.serialize_field("thread", "same-original-thread-history-only")?;
        state.serialize_field("original", original)?;
        state.serialize_field("body", body)?;
        state.serialize_field("artifact", artifact)?;
        state.serialize_field("context", context)?;
        state.serialize_field("terminal", terminal)?;
        state.serialize_field("received", received)?;
        state.serialize_field("verified", verified)?;
        state.serialize_field("dispatched", dispatched)?;
        state.serialize_field("published", published)?;
        state.end()
    }
}
