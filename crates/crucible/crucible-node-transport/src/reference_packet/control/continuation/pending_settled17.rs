//! Borrows both independently retained decoded Control and model records.

use super::*;
use crate::retained_metadata::MetadataObserver;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct PendingHistory17<'a>(&'a PacketDecodedControlSnapshot);

impl Serialize for PendingHistory17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketDecodedControlSnapshot { record, model } = self.0;
        let mut fields = serializer.serialize_struct("NativePendingDecodedControl17", 3)?;
        fields.serialize_field("schema", "source-private.native-pending-decoded-control/17")?;
        fields.serialize_field("record", record)?;
        fields.serialize_field("model", &model.borrowed_settled_model_data())?;
        fields.end()
    }
}

impl PacketDecodedControlSnapshot {
    /// Borrows the actual independent decoded record owners as historical data.
    pub(crate) fn borrowed_settled_history_data(&self) -> impl Serialize + '_ {
        PendingHistory17(self)
    }

    /// Appends both actual record owners under one enclosing metadata pass.
    ///
    /// # Errors
    /// Refuses finite observer exhaustion or checked retained-layout overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self { record, model } = self;
        record.observe_settled_history_metadata_data(observer)?;
        observer.observe(model)
    }
}
