//! Streams the actual common base beside its complete Initial15 Node history.
//!
//! The surrounding Node17 view preserves installed custody separately. This
//! view borrows every common field; the original semantic5 writer and its
//! refusal of installed custody remain unchanged.

use super::*;

/// Borrows the common fields of a genuinely installed Initial15 node.
pub(in crate::node_adapters::cnp::semantic) struct RestoredBaseCustodyView<'a>(
    pub(in crate::node_adapters::cnp::semantic) &'a SemanticRuntimeCustody,
);

impl Serialize for RestoredBaseCustodyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let state = self.0;
        let SemanticRuntimeCustody {
            installed_restoration,
            arm_attempt,
            ready,
            prepared_owner,
            activate_response,
            observe_sequence,
            activation_attempt,
            active,
            inputs: _,
            operations: _,
            watermark,
            observation,
            reclaimed,
            credit,
            quarantined,
        } = state;
        if installed_restoration.is_none() {
            return Err(serde::ser::Error::custom(
                "restored Node base requires actual installed custody",
            ));
        }
        let observation = observation
            .as_ref()
            .map(|(world, value)| (activation(world), value));
        let reclaimed = reclaimed
            .as_ref()
            .map(|value| (&value.owner, &value.receipt));

        let mut row = serializer.serialize_struct("RestoredSemanticBase", 15)?;
        row.serialize_field("schema", "source-owned.packet-semantic-base/17")?;
        row.serialize_field(
            "arm_attempt",
            &arm_attempt.as_ref().map(ActivationView::from),
        )?;
        row.serialize_field("ready", ready)?;
        row.serialize_field("prepared_owner", prepared_owner)?;
        row.serialize_field("activate_response", activate_response)?;
        row.serialize_field("observe_sequence", observe_sequence)?;
        row.serialize_field(
            "activation_attempt",
            &activation_attempt.as_ref().map(activation),
        )?;
        row.serialize_field("active", &active.as_ref().map(activation))?;
        row.serialize_field("inputs", &Inputs(state))?;
        row.serialize_field("operations", &Operations(state))?;
        row.serialize_field("watermark", watermark)?;
        row.serialize_field("observation", &observation)?;
        row.serialize_field("reclaimed", &reclaimed)?;
        row.serialize_field("retained_credit", &credit.retained_bytes())?;
        row.serialize_field("quarantined", quarantined)?;
        row.end()
    }
}

/// Counts the defining borrowed base fields and simultaneous projection headers.
pub(in crate::node_adapters::cnp::semantic) fn counter_scratch_data() -> usize {
    use crate::{node_contract::OwnerIdentity, node_scheduling::NativeSchedulingObservation};
    use crucible_node_format::ContentRef;
    use std::mem::size_of;

    // Each destructured field is a shared reference to a Sized field. The
    // original state reference and the view remain independent fixed headers.
    size_of::<RestoredBaseCustodyView<'static>>()
        + 16 * size_of::<&'static SemanticRuntimeCustody>()
        + size_of::<Option<ActivationView<'static>>>() * 3
        + size_of::<
            Option<(
                ActivationView<'static>,
                &'static NativeSchedulingObservation,
            )>,
        >()
        + size_of::<Option<(&'static OwnerIdentity, &'static ContentRef)>>()
        + size_of::<Inputs<'static>>()
        + size_of::<Operations<'static>>()
        + size_of::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstalled_base_cannot_select_the_restored_format() {
        let state = SemanticRuntimeCustody::default();

        assert!(serde_json::to_value(RestoredBaseCustodyView(&state)).is_err());
        let original = serde_json::to_value(CustodyView(&state)).unwrap();
        assert_eq!(original["schema"], "source-owned.packet-semantic-custody/5");
        assert_eq!(original.as_object().unwrap().len(), 15);
    }
}
