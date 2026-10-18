//! Shares the fixed Owned11 snapshot schema between its writer and pure counter.

use crate::ProviderError;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;

pub(super) struct NativeOwned11SnapshotContractValue;

impl serde::Serialize for NativeOwned11SnapshotContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-native-continuation-contract/11"),
            ),
            ("snapshot", V::Text(super::SCHEMA)),
            (
                "fields",
                V::Array(&[
                    V::Text("capture"),
                    V::Text("capture_request"),
                    V::Text("control"),
                    V::Text("control_reference"),
                    V::Text("endpoint"),
                    V::Text("protocol"),
                    V::Text("schema"),
                ]),
            ),
            (
                "protocol",
                V::Array(&[
                    V::Text(super::BEFORE_TAG),
                    V::Text(
                        "full application/json CNP blob reference of exact original encoded protocol bytes",
                    ),
                    V::Text("actual original encoded Vec capacity"),
                    V::Text("complete compact-bytes/7 literal bytes"),
                ]),
            ),
            (
                "endpoint",
                V::Text(
                    "exact native-endpoint-state/11 fourteen-field tuple; full original histories, capacities, Hello, pins, sequences and held Capture boundary",
                ),
            ),
            (
                "identity",
                V::Text(
                    "never parse and canonicalize the embedded original protocol; raw serde field order, numeric representation and alias-view bytes are preserved",
                ),
            ),
            (
                "admission",
                V::Text(
                    "count complete encoded compact leaf before copying; separately admit original capacity, snapshot output, bounded parser/typed history/Control/model and canonical scratch; finite encoded bounds are not physical allocation authority",
                ),
            ),
            (
                "validation",
                V::Text(
                    "exact before fullref and capacity, full native protocol decoder and alias manifest, full endpoint history/blob/correlation correspondence, pending Control/model transition and original terminal/fourth-Poll journal are all required",
                ),
            ),
            (
                "authority",
                V::Text(
                    "historical data only; no source ticket, live registrar, fresh key activation or semantic Arm/Capture permission",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

/// Counts the same compiled borrowed schema without creating its DOM or bytes.
///
/// # Errors
/// Refuses finite-counter exhaustion or checked requested-layout overflow.
pub(crate) fn native_owned11_snapshot_contract_storage_data(
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &NativeOwned11SnapshotContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::canonical;

    #[test]
    fn defining_borrowed_roster_preserves_original_canonical_contract_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        // Keep the original factory projection as an independent byte regression.
        let expected = canonical::canonical_json(&serde_json::json!({
            "schema":"source-owned.packet-native-continuation-contract/11",
            "snapshot":super::super::SCHEMA,
            "fields":["capture","capture_request","control","control_reference","endpoint","protocol","schema"],
            "protocol":[super::super::BEFORE_TAG,"full application/json CNP blob reference of exact original encoded protocol bytes","actual original encoded Vec capacity","complete compact-bytes/7 literal bytes"],
            "endpoint":"exact native-endpoint-state/11 fourteen-field tuple; full original histories, capacities, Hello, pins, sequences and held Capture boundary",
            "identity":"never parse and canonicalize the embedded original protocol; raw serde field order, numeric representation and alias-view bytes are preserved",
            "admission":"count complete encoded compact leaf before copying; separately admit original capacity, snapshot output, bounded parser/typed history/Control/model and canonical scratch; finite encoded bounds are not physical allocation authority",
            "validation":"exact before fullref and capacity, full native protocol decoder and alias manifest, full endpoint history/blob/correlation correspondence, pending Control/model transition and original terminal/fourth-Poll journal are all required",
            "authority":"historical data only; no source ticket, live registrar, fresh key activation or semantic Arm/Capture permission"
        }))?;
        let actual = super::super::native_owned11_snapshot_contract()?;
        assert_eq!(actual, expected);
        let quote = native_owned11_snapshot_contract_storage_data(usize::MAX)?;
        assert!(actual.len() <= quote.maximum_encoded_bytes);
        assert!(quote.canonical_output_requested_bytes >= actual.len());
        Ok(())
    }
}
