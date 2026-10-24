//! Reads the exact closed typed Position and numeric Phase history grammar.
//!
//! Actual Phase serialization emits only the integer0..3. These cold fields
//! are typed currency/report coordinates; accepting them creates no original
//! actor, completed report, source selection or reconstruction authority.

use super::{HistoricalType, Ledger, invalid};
use crate::ProviderError;
use crucible_node_format::{Phase, Position, U64};

impl HistoricalType for Phase {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let value = match input {
            b"0" => Self::BoundaryControl,
            b"1" => Self::Publication,
            b"2" => Self::Delivery,
            b"3" => Self::Reaction,
            _ => return Err(invalid()),
        };
        Ok(build.then_some(value))
    }
}

historical_struct!(Position {
    time_ps: U64,
    microstep: U64,
    phase: Phase,
});

// crucible-lint: allow panic-shortcut -- actual canonical type decoding and malformed controls are the observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual typed cold Position reconstruction is the test observation"
)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::records::ValidatedMetadataRecords;

    fn read(input: &[u8], build: bool) -> Result<Option<Position>, ProviderError> {
        let records = ValidatedMetadataRecords::validate(b"[]", 0, 0)?;
        let mut ledger = Ledger::new(
            records.rows(),
            HistoricalJsonLimits {
                maximum_input_bytes: 512,
                maximum_nodes: 4,
                maximum_depth: 8,
                maximum_owned_backing_bytes: 0,
                maximum_tree_entries: 3,
            },
        );
        let value = ledger.read::<Position>(input, build)?;
        if ledger.rows.next().is_some() {
            return Err(invalid());
        }
        Ok(value)
    }

    #[test]
    fn actual_position_serializer_round_trips_all_four_phases_without_rows() {
        for phase in [
            Phase::BoundaryControl,
            Phase::Publication,
            Phase::Delivery,
            Phase::Reaction,
        ] {
            let actual = Position::new(U64::new(u64::MAX), U64::new(19), phase);
            // Protocol metadata serializes typed structs in declaration order;
            // canonical JSON is independently checked only for raw report banks.
            let bytes = serde_json::to_vec(&actual).unwrap();
            assert_eq!(read(&bytes, false).unwrap(), None);
            assert_eq!(read(&bytes, true).unwrap(), Some(actual));
        }
    }

    #[test]
    fn position_rejects_extra_missing_wrong_and_out_of_range_fields() {
        for input in [
            br#"{"time_ps":"1","microstep":"0","phase":4}"#.as_slice(),
            br#"{"time_ps":"1","microstep":"0","phase":-1}"#.as_slice(),
            br#"{"time_ps":"1","microstep":"0","phase":"1"}"#.as_slice(),
            br#"{"time_ps":"1","microstep":"0","phase":1e0}"#.as_slice(),
            br#"{"time_ps":"1","microstep":"0"}"#.as_slice(),
            br#"{"time_ps":"1","microstep":"0","phase":1,"extra":true}"#.as_slice(),
            br#"{"time_ps":"1","microstep":0,"phase":1}"#.as_slice(),
        ] {
            assert!(read(input, false).is_err());
            assert!(read(input, true).is_err());
        }
    }
}

#[path = "position/native17_build.rs"]
mod native17_build;
