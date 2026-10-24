//! Reads modeled Capture once state without reconstructing live custody.
//!
//! ```text
//! {schema,cut,phase,once_spent,failed,prefix_frontier,frontier,bridge}
//! ```
//!
//! Completed state delegates the existing Bridge reader, which joins exact SDK
//! originals/terminals, native checkpoint and immutable Source MAC evidence.
//! Preencoder state has a separate result type and never yields completion.

use super::capture_bridge_reader::OriginalSourceRestoredCaptureAdminBridgeHistory17Read as Bridge;
use super::producer_fields::{field, object};
use crate::node_contract::{RuntimeError, SavedRuntimeActivation};
use crucible_node_format::{ContentRef, U64};
use crucible_node_transport::{
    protocol_snapshot::{
        current_controller17::{
            ValidatedControllerSettledHistory17, ValidatedHistoricalRestoredSettledCapture17,
        },
        restored_settled17::SealedHistoricalRestoredSettledNative17,
    },
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::complete_restore::PacketNativeRestoredRecord,
    },
};
use serde_json::Value;
use std::mem::size_of;

const SCHEMA: &str = "source-private.source-capture-housekeeping/17";
const FIELDS: [&str; 8] = [
    "schema",
    "cut",
    "phase",
    "once_spent",
    "failed",
    "prefix_frontier",
    "frontier",
    "bridge",
];

/// Retains only an unused or fully authenticated settled Capture ledger.
///
/// This DATA cannot open a Source loan or spend another native operation. The
/// parent retains the actual raw history and admits all SDK/native validation.
pub(crate) struct OriginalSourceCaptureHousekeeping17Read {
    bridge: Option<Bridge>,
}

/// Retains the observed preencoder prefix as DATA, independently of completion.
///
/// The parent must join the exact prefix content and final Source/SDK/native
/// evidence before accepting its enclosing archive. This type exposes neither
/// a completed frontier nor a conversion to a settled ledger or live owner.
pub(crate) struct OriginalSourcePreEncoderCaptureHousekeeping17Read {
    prefix_frontier: U64,
}

struct Fields<'a> {
    cut: &'a str,
    phase: &'a str,
    once_spent: bool,
    prefix: Option<U64>,
    frontier: Option<U64>,
    bridge: &'a Value,
}

fn fields_data(history: &Value) -> Result<Fields<'_>, RuntimeError> {
    let root = object(history, &FIELDS)?;
    if field(root, "schema")?.as_str() != Some(SCHEMA)
        || field(root, "failed")?.as_bool() != Some(false)
    {
        return Err(RuntimeError::OutstandingObligations);
    }
    Ok(Fields {
        cut: field(root, "cut")?.as_str().ok_or_else(invalid)?,
        phase: field(root, "phase")?.as_str().ok_or_else(invalid)?,
        once_spent: field(root, "once_spent")?.as_bool().ok_or_else(invalid)?,
        prefix: optional_frontier_data(field(root, "prefix_frontier")?)?,
        frontier: optional_frontier_data(field(root, "frontier")?)?,
        bridge: field(root, "bridge")?,
    })
}

// U64's closed decimal-string grammar is checked without cloning a Value or
// creating a decimal String/typed decoder allocation.
fn optional_frontier_data(value: &Value) -> Result<Option<U64>, RuntimeError> {
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or_else(invalid)?;
    if text.is_empty()
        || text.len() > 20
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || text.len() > 1 && text.starts_with('0')
    {
        return Err(invalid());
    }
    Ok(Some(U64::new(text.parse::<u64>().map_err(|_| invalid())?)))
}

fn settled_fields_data(history: &Value) -> Result<Fields<'_>, RuntimeError> {
    let fields = fields_data(history)?;
    if fields.cut != "settled" {
        return Err(invalid());
    }
    match fields.phase {
        "unused"
            if !fields.once_spent
                && fields.prefix.is_none()
                && fields.frontier.is_none()
                && fields.bridge.is_null() =>
        {
            Ok(fields)
        }
        "complete"
            if fields.once_spent
                && !fields.bridge.is_null()
                && fields
                    .prefix
                    .zip(fields.frontier)
                    .is_some_and(|(prefix, frontier)| prefix < frontier) =>
        {
            Ok(fields)
        }
        _ => Err(RuntimeError::OutstandingObligations),
    }
}

fn preencoder_fields_data(history: &Value) -> Result<Fields<'_>, RuntimeError> {
    let fields = fields_data(history)?;
    if fields.cut != "pre_encoder"
        || fields.phase != "preparing"
        || !fields.once_spent
        || fields.frontier.is_some()
        || !fields.bridge.is_null()
        || fields.prefix.is_none()
    {
        return Err(invalid());
    }
    Ok(fields)
}

impl OriginalSourceCaptureHousekeeping17Read {
    /// Joins a settled ledger to exact existing SDK/native Bridge evidence.
    ///
    /// An unused Source requires the actual validated SDK Capture slot absent.
    /// Complete requires the existing Bridge's independently authenticated
    /// prefix/final frontiers. Every active/preencoder/failed state refuses.
    ///
    /// # Errors
    /// Refuses unknown fields, noncanonical counters, changed phase/once state,
    /// mismatched SDK custody, or any underlying SDK/native/World/MAC join.
    pub(crate) fn validate_settled_data(
        history: &Value,
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        world: &SavedRuntimeActivation,
        checkpoint: (
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &ContentRef,
            U64,
        ),
        maximum_transcript: usize,
    ) -> Result<Self, RuntimeError> {
        let fields = settled_fields_data(history)?;
        match fields.phase {
            "unused" => {
                let controller = controller
                    .parts_data()
                    .map_err(|_| invalid())?
                    .as_object()
                    .ok_or_else(invalid)?;
                if !field(controller, "capture")?.is_null() {
                    return Err(invalid());
                }
                Ok(Self { bridge: None })
            }
            "complete" => {
                let prefix = fields.prefix.ok_or_else(invalid)?;
                let frontier = fields.frontier.ok_or_else(invalid)?;
                if !fields.once_spent || prefix >= frontier || fields.bridge.is_null() {
                    return Err(invalid());
                }
                let bridge = Bridge::validate_data(
                    fields.bridge,
                    controller,
                    native,
                    world,
                    checkpoint,
                    maximum_transcript,
                )?;
                if bridge.prefix_checkpoint_data().2 != prefix
                    || bridge.completed_frontier_data() != frontier
                {
                    return Err(invalid());
                }
                Ok(Self {
                    bridge: Some(bridge),
                })
            }
            _ => Err(RuntimeError::OutstandingObligations),
        }
    }

    /// Borrows the same independently validated Bridge, if this ledger completed.
    pub(crate) fn bridge_data(&self) -> Option<&Bridge> {
        self.bridge.as_ref()
    }

    /// Returns a completed SDK frontier only for an authenticated settled ledger.
    pub(crate) fn completed_frontier_data(&self) -> Option<U64> {
        self.bridge.as_ref().map(Bridge::completed_frontier_data)
    }

    /// Counts exact retained typed SDK backing without rebuilding live custody.
    ///
    /// # Errors
    /// Refuses defining metadata/layout overflow or the supplied actual ceiling.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let backing = self
            .bridge
            .as_ref()
            .map(|bridge| bridge.retained_requested_storage_data(maximum))
            .transpose()?
            .unwrap_or(0);
        size_of::<Self>()
            .checked_add(backing)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Counts fixed pure reader controls, excluding separately admitted SDK work.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<Fields<'static>>()
            + size_of::<Result<Fields<'static>, RuntimeError>>()
            + size_of::<Option<U64>>() * 2
            + size_of::<U64>() * 2
            + size_of::<Result<Bridge, RuntimeError>>()
            + size_of::<&Value>()
            + size_of::<[&str; 8]>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<Result<u64, std::num::ParseIntError>>()
    }
}

impl OriginalSourcePreEncoderCaptureHousekeeping17Read {
    /// Checks a Preparing witness against the actual completed SDK prefix cut.
    ///
    /// The SDK loan already joined its real originals/terminals and final cut.
    /// This only checks the archived scalar preencoder boundary; the enclosing
    /// Source reader must still authenticate exact prefix content and final
    /// native/Bridge evidence. Preparing is never promoted to Complete here.
    ///
    /// # Errors
    /// Refuses another cut, a partial/failed state, changed SDK prefix frontier,
    /// missing/extra fields, noncanonical counters or any fabricated completion.
    pub(crate) fn validate_data(
        history: &Value,
        sdk: &ValidatedHistoricalRestoredSettledCapture17,
    ) -> Result<Self, RuntimeError> {
        let fields = preencoder_fields_data(history)?;
        if fields.prefix != Some(sdk.prefix_frontier_data()) {
            return Err(invalid());
        }
        Ok(Self {
            prefix_frontier: sdk.prefix_frontier_data(),
        })
    }

    /// Returns only the actual saved prefix frontier as historical comparison DATA.
    pub(crate) fn prefix_frontier_data(&self) -> U64 {
        self.prefix_frontier
    }

    /// Counts this fixed scalar DATA result; it owns no historical SDK copy.
    pub(crate) const fn retained_requested_storage_data(&self) -> usize {
        size_of::<Self>()
    }
}

fn invalid() -> RuntimeError {
    RuntimeError::InvalidReceipt
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn preencoder() -> Value {
        json!({"schema":SCHEMA,"cut":"pre_encoder","phase":"preparing",
            "once_spent":true,"failed":false,"prefix_frontier":"7","frontier":null,"bridge":null})
    }

    #[test]
    fn preencoder_never_parses_as_settled_or_manufactured_complete() {
        let original = preencoder();
        assert_eq!(
            preencoder_fields_data(&original).unwrap().prefix,
            Some(U64::new(7))
        );
        assert!(settled_fields_data(&original).is_err());

        for (name, value) in [
            ("phase", json!("complete")),
            ("frontier", json!("8")),
            ("bridge", json!({})),
            ("once_spent", json!(false)),
            ("failed", json!(true)),
        ] {
            let mut changed = original.clone();
            changed[name] = value;
            assert!(
                preencoder_fields_data(&changed).is_err(),
                "accepted changed {name}"
            );
        }
    }

    #[test]
    fn every_field_is_mandatory_and_extensions_are_rejected() {
        for name in FIELDS {
            let mut changed = preencoder();
            changed.as_object_mut().unwrap().remove(name);
            assert!(fields_data(&changed).is_err(), "accepted missing {name}");
        }
        let mut changed = preencoder();
        changed["completed"] = json!(true);
        assert!(fields_data(&changed).is_err());
    }

    #[test]
    fn settled_active_and_failed_phases_refuse_instead_of_resetting_once() {
        for phase in ["preparing", "prepared", "capturing", "confirming", "failed"] {
            let mut changed = preencoder();
            changed["cut"] = json!("settled");
            changed["phase"] = json!(phase);
            assert!(settled_fields_data(&changed).is_err(), "accepted {phase}");
        }
        let mut unused = preencoder();
        unused["cut"] = json!("settled");
        unused["phase"] = json!("unused");
        unused["once_spent"] = json!(false);
        unused["prefix_frontier"] = Value::Null;
        assert!(settled_fields_data(&unused).is_ok());
        unused["once_spent"] = json!(true);
        assert!(settled_fields_data(&unused).is_err());
    }

    #[test]
    fn frontier_uses_the_closed_canonical_u64_string_grammar() {
        for invalid in [
            json!("07"),
            json!("+7"),
            json!(""),
            json!("-1"),
            json!("18446744073709551616"),
            json!("7.0"),
            json!("7e0"),
            json!(7),
            json!(true),
        ] {
            assert!(
                optional_frontier_data(&invalid).is_err(),
                "accepted {invalid}"
            );
        }
        assert_eq!(
            optional_frontier_data(&json!("18446744073709551615")).unwrap(),
            Some(U64::new(u64::MAX))
        );
        assert_eq!(
            optional_frontier_data(&json!("0")).unwrap(),
            Some(U64::new(0))
        );
    }
}
