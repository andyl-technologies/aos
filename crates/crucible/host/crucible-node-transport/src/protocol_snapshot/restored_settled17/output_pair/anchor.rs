//! Checks every unchanged-cut5 anchor field without reconstructing an Envelope.

use super::*;

pub(super) fn capture(expected: &CaptureArguments, input: &[u8]) -> Result<(), ProviderError> {
    closed(
        input,
        &[
            "capture_id",
            "participant_ids",
            "cut_id",
            "cut",
            "event_ordinal",
            "ordering_profile",
            "preservation_contract",
        ],
    )?;
    text(field(input, "capture_id")?, expected.capture_id.as_str())?;
    text(field(input, "cut_id")?, expected.cut_id.as_str())?;
    position(field(input, "cut")?, expected.cut)?;
    if decimal(field(input, "event_ordinal")?)? != expected.event_ordinal.get() {
        return Err(invalid());
    }
    text(
        field(input, "ordering_profile")?,
        &expected.ordering_profile,
    )?;
    text(
        field(input, "preservation_contract")?,
        expected.preservation_contract.as_str(),
    )?;
    let mut ids = Fields::array(field(input, "participant_ids")?)?;
    for id in &expected.participant_ids {
        text(ids.next()?.ok_or_else(invalid)?, id.as_str())?;
    }
    ids.finish()
}

pub(super) fn authenticate(
    input: &[u8],
    before: &NativeCurrentGraph17Data,
    original: &Envelope,
    arguments: &CaptureArguments,
    begin: &BeginRequest,
    boundary: &PacketModelCaptureBoundaryData,
    control: &ContentRef,
) -> Result<(), ProviderError> {
    if input.len() > 8192 {
        return Err(invalid());
    }
    // This is the unchanged, canonical schema5 anchor, not a new native17 cast.
    let mut f = Fields::object(input)?;
    hash(f.named("binding")?, &begin.binding_hash)?;
    capture(arguments, f.named("capture")?)?;
    crate::protocol_snapshot::owned11::correspondence::content_reference(
        control,
        f.named("control_snapshot")?,
    )?;
    hash(f.named("inventory_hash")?, &boundary.inventory_hash)?;
    position(f.named("local_cursor")?, boundary.local_cursor)?;
    if decimal(f.named("native_pid")?)? != u64::from(before.creator_data()) {
        return Err(invalid());
    }
    crate::protocol_snapshot::owned11::correspondence::envelope(original, f.named("request")?)?;
    let request_hash = original.request_hash(RequestOrigin::Controller)?;
    hash(f.named("request_hash")?, &request_hash)?;
    text(
        f.named("schema")?,
        "source-owned.packet-native-unchanged-cut/5",
    )?;
    hash(
        f.named("world")?,
        &before.current_control_data().selection_data().world,
    )?;
    f.finish()
}

fn decimal(input: &[u8]) -> Result<u64, ProviderError> {
    let text = plain_string(input)?;
    if text.is_empty() || text.len() > 1 && text.starts_with('0') {
        return Err(invalid());
    }
    unsigned(text.as_bytes())
}

fn text(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

fn hash(input: &[u8], expected: &HashRef) -> Result<(), ProviderError> {
    expected.validate()?;
    closed(input, &["algorithm", "domain", "digest"])?;
    text(field(input, "algorithm")?, &expected.algorithm)?;
    text(field(input, "domain")?, &expected.domain)?;
    text(field(input, "digest")?, &expected.digest)
}

fn position(input: &[u8], expected: Position) -> Result<(), ProviderError> {
    closed(input, &["time_ps", "microstep", "phase"])?;
    if decimal(field(input, "time_ps")?)? != expected.time_ps.get()
        || decimal(field(input, "microstep")?)? != expected.microstep.get()
        || unsigned(field(input, "phase")?)? != expected.phase as u64
    {
        return Err(invalid());
    }
    Ok(())
}

fn closed(input: &[u8], names: &[&str]) -> Result<(), ProviderError> {
    let mut f = Fields::object(input)?;
    let mut seen = 0usize;
    while let Some((key, _)) = f.pair()? {
        let key = plain_string(key)?;
        let index = names
            .iter()
            .position(|name| *name == key)
            .ok_or_else(invalid)?;
        let bit = 1usize
            .checked_shl(u32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if seen & bit != 0 {
            return Err(invalid());
        }
        seen |= bit;
    }
    f.finish()?;
    if seen
        != 1usize
            .checked_shl(u32::try_from(names.len()).map_err(|_| invalid())?)
            .ok_or_else(invalid)?
            - 1
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Id, Phase, canonical};

    fn arguments() -> CaptureArguments {
        CaptureArguments {
            capture_id: Id::new("capture").unwrap(),
            participant_ids: vec![Id::new("a").unwrap(), Id::new("b").unwrap()],
            cut_id: Id::new("cut").unwrap(),
            cut: Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl),
            event_ordinal: U64::new(2),
            ordering_profile: "superdense-v1".into(),
            preservation_contract: Id::new("source-owned.packet-complete-original-lineage/5")
                .unwrap(),
        }
    }

    #[test]
    fn capture_comparison_preserves_every_participant_and_coordinate() {
        let expected = arguments();
        let mut value = serde_json::to_value(&expected).unwrap();
        let raw = canonical::canonical_json(&value).unwrap();
        capture(&expected, &raw).unwrap();

        value["participant_ids"] = serde_json::json!(["b", "a"]);
        assert!(capture(&expected, &canonical::canonical_json(&value).unwrap()).is_err());
        value = serde_json::to_value(&expected).unwrap();
        value["cut"]["microstep"] = serde_json::json!("1");
        assert!(capture(&expected, &canonical::canonical_json(&value).unwrap()).is_err());
    }

    #[test]
    fn closed_anchor_children_reject_duplicate_or_extra_fields() {
        assert!(
            closed(
                br#"{"phase":0,"phase":0,"time_ps":"0","microstep":"0"}"#,
                &["time_ps", "microstep", "phase"]
            )
            .is_err()
        );
        assert!(
            closed(
                br#"{"phase":0,"time_ps":"0","microstep":"0","extra":null}"#,
                &["time_ps", "microstep", "phase"]
            )
            .is_err()
        );
    }
}
