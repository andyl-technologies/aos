//! Checks the RFC-0010 T-API-5 open-set payload model.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::test_support::condition_payload_entry_for_test;
use crucible::{
    Decision, EventAttributeValue, EventPayload, RngDecision, RngStreamId, SchedulerEventLogClass,
    SchedulerEventLogPayload, VirtualTime, event_kind_catalog,
};
use crucible_api::{
    OPEN_SET_CAPABILITY_CATEGORIES, OpenSetAttributeValue, OpenSetPayload, OpenSetPayloadCategory,
    OpenSetPayloadError, RPC_OPEN_SET_PAYLOAD_KINDS, ReceivedOpenSetEventPayload,
    current_open_set_capabilities, open_set_breakpoint_kind, open_set_command_kind,
    open_set_event_envelope_from_entry, open_set_payload_from_event_payload,
    receive_open_set_event_payload, session_command_for_open_set_command_kind,
    validate_open_set_send_payload,
};
use crucible_session::{BreakpointSpec, SessionCommandKind};

#[test]
fn open_set_payload_model_runs_named_checks() {
    assert_capabilities_advertise_dotted_categories_and_kinds();
    assert_event_payload_conversion_reuses_event_log_catalog();
    assert_unknown_event_kinds_are_opaque();
    assert_send_validation_uses_typed_unsupported_and_invalid_argument();
    assert_existing_command_and_breakpoint_vocabularies_are_adapted();
}

#[test]
fn capabilities_advertise_dotted_categories_and_kinds() {
    assert_capabilities_advertise_dotted_categories_and_kinds();
}

fn assert_capabilities_advertise_dotted_categories_and_kinds() {
    assert_eq!(RPC_OPEN_SET_PAYLOAD_KINDS, OPEN_SET_CAPABILITY_CATEGORIES);

    let capabilities = current_open_set_capabilities();
    assert!(!capabilities.commands.is_empty());
    assert!(!capabilities.breakpoints.is_empty());
    assert_eq!(
        capabilities.event_payloads.len(),
        event_kind_catalog().len()
    );

    assert!(
        capabilities
            .commands
            .iter()
            .any(|schema| schema.kind == "crucible.cmd.continue")
    );
    assert!(
        capabilities
            .breakpoints
            .iter()
            .any(|schema| schema.kind == "crucible.bp.quiescent")
    );
    assert!(
        capabilities
            .event_payloads
            .iter()
            .any(|schema| schema.kind == "crucible.event.rng_draw")
    );

    for schema in capabilities
        .commands
        .iter()
        .chain(capabilities.breakpoints.iter())
        .chain(capabilities.event_payloads.iter())
    {
        assert!(schema.kind.starts_with(schema.category.prefix()));
        let local_kind = &schema.kind[schema.category.prefix().len()..];
        assert!(!local_kind.is_empty());
        assert!(!local_kind.contains(".."));
    }

    for catalog_entry in event_kind_catalog() {
        let wire_kind = format!("crucible.event.{}", catalog_entry.kind());
        let schema = capabilities
            .schema_for(OpenSetPayloadCategory::Event, &wire_kind)
            .unwrap_or_else(|| panic!("missing API event schema for {wire_kind}"));
        assert_eq!(
            schema.attributes,
            catalog_entry
                .attributes()
                .iter()
                .map(|attribute| (*attribute).to_owned())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn event_payload_conversion_reuses_event_log_catalog() {
    assert_event_payload_conversion_reuses_event_log_catalog();
}

fn assert_event_payload_conversion_reuses_event_log_catalog() {
    let entry = condition_payload_entry_for_test(
        9,
        VirtualTime { ticks: 17 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("api-open-set"),
            value: 41,
        })),
    );

    let event = open_set_event_envelope_from_entry(&entry);
    assert_eq!(event.sequence, entry.sequence());
    assert_eq!(event.at.virtual_time_ticks, 17);
    assert_eq!(event.at.icount_retired, entry.time().icount.icount.retired);
    assert_eq!(event.level, entry.level());
    assert!(!event.observational);
    assert_eq!(entry.class(), SchedulerEventLogClass::Causal);
    assert_eq!(event.payload.kind, "crucible.event.rng_draw");
    assert_eq!(
        event.payload.attribute("stream_name"),
        Some(&OpenSetAttributeValue::String(String::from("api-open-set")))
    );
    assert_eq!(
        event.payload.attribute("value"),
        Some(&OpenSetAttributeValue::Uint(41))
    );

    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("name"),
        EventAttributeValue::String(String::from("open-set-diagnostic")),
    );
    let payload = EventPayload::new("diagnostic", attributes);
    let api_payload = open_set_payload_from_event_payload(&payload);
    assert_eq!(api_payload.kind, "crucible.event.diagnostic");
    assert_eq!(
        api_payload.attribute("name"),
        Some(&OpenSetAttributeValue::String(String::from(
            "open-set-diagnostic"
        )))
    );
}

#[test]
fn unknown_event_kinds_are_opaque() {
    assert_unknown_event_kinds_are_opaque();
}

fn assert_unknown_event_kinds_are_opaque() {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("opaque_id"),
        OpenSetAttributeValue::String(String::from("future-event")),
    );
    let payload = OpenSetPayload::new("crucible.event.future_kind", attributes.clone());
    let received = receive_open_set_event_payload(payload);

    assert!(received.is_opaque());
    assert_eq!(
        received,
        ReceivedOpenSetEventPayload::Opaque(OpenSetPayload::new(
            "crucible.event.future_kind",
            attributes,
        ))
    );

    let known = receive_open_set_event_payload(OpenSetPayload::empty("crucible.event.rng_draw"));
    assert!(matches!(known, ReceivedOpenSetEventPayload::Known(_)));
}

#[test]
fn send_validation_uses_typed_unsupported_and_invalid_argument() {
    assert_send_validation_uses_typed_unsupported_and_invalid_argument();
}

fn assert_send_validation_uses_typed_unsupported_and_invalid_argument() {
    let unsupported = validate_open_set_send_payload(
        OpenSetPayloadCategory::Command,
        &OpenSetPayload::empty("crucible.cmd.future-command"),
    );
    assert_eq!(
        unsupported,
        Err(OpenSetPayloadError::UnsupportedKind {
            category: OpenSetPayloadCategory::Command,
            kind: String::from("crucible.cmd.future-command"),
        })
    );

    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("unexpected"),
        OpenSetAttributeValue::Bool(true),
    );
    let invalid = validate_open_set_send_payload(
        OpenSetPayloadCategory::Command,
        &OpenSetPayload::new("crucible.cmd.continue", attributes),
    );
    assert_eq!(
        invalid,
        Err(OpenSetPayloadError::InvalidArgument {
            category: OpenSetPayloadCategory::Command,
            kind: String::from("crucible.cmd.continue"),
            argument: String::from("unexpected"),
            reason: String::from("attribute is not declared for this kind"),
        })
    );

    assert_eq!(
        validate_open_set_send_payload(
            OpenSetPayloadCategory::Command,
            &OpenSetPayload::empty("crucible.cmd.continue"),
        ),
        Ok(())
    );
}

#[test]
fn existing_command_and_breakpoint_vocabularies_are_adapted() {
    assert_existing_command_and_breakpoint_vocabularies_are_adapted();
}

fn assert_existing_command_and_breakpoint_vocabularies_are_adapted() {
    assert_eq!(
        open_set_command_kind(SessionCommandKind::Continue),
        Some(String::from("crucible.cmd.continue"))
    );
    assert_eq!(
        session_command_for_open_set_command_kind("crucible.cmd.continue"),
        Some(SessionCommandKind::Continue)
    );

    let breakpoint = BreakpointSpec::suspend_once(crucible::Condition::Quiescent);
    assert_eq!(
        open_set_breakpoint_kind(&breakpoint.predicate),
        "crucible.bp.quiescent"
    );
}
