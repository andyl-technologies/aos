//! API-side checks for the thin session command mapping.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible_api::{
    API_COMMAND_MAPPINGS, API_METHOD_MAPPINGS, ApiDispatch, ApiMethod, ApiRequestShape,
    CommandDispatchCardinality, api_command_for_session_command, method_mapping,
    session_command_for_api_command, validate_thin_api_mapping,
};
use crucible_session::{LiveQueryKind, SessionCommandKind};

#[test]
fn api_session_mapping_validates_thin_wrapper_contract() {
    validate_thin_api_mapping()
        .unwrap_or_else(|error| panic!("API mapping should remain session-thin: {error}"));
}

#[test]
fn api_mapping_covers_every_session_command_kind_exactly_once() {
    assert_eq!(API_COMMAND_MAPPINGS.len(), SessionCommandKind::ALL.len());

    for command in SessionCommandKind::ALL {
        let mapping = api_command_for_session_command(command)
            .unwrap_or_else(|| panic!("missing API command mapping for {command:?}"));
        assert_eq!(
            session_command_for_api_command(mapping.command_name),
            Some(command)
        );
    }
}

#[test]
fn api_methods_are_thin_programmatic_mappings() {
    assert_eq!(API_METHOD_MAPPINGS.len(), ApiMethod::ALL.len());

    for method in ApiMethod::ALL {
        let mapping =
            method_mapping(method).unwrap_or_else(|| panic!("missing API mapping for {method:?}"));
        assert_eq!(mapping.request_shape, ApiRequestShape::TypedProgrammatic);
        assert!(!mapping.request_shape.is_browser_shaped());
        assert!(
            mapping.dispatch.is_thin_wrapper(),
            "{} must map to session primitives",
            method.name(),
        );
    }

    assert_eq!(
        method_mapping(ApiMethod::CreateSession)
            .and_then(|mapping| mapping.dispatch.fixed_session_command()),
        Some(SessionCommandKind::Start),
    );
    assert_eq!(
        method_mapping(ApiMethod::ListSessions).and_then(|mapping| mapping.dispatch.mirror_query()),
        Some(LiveQueryKind::Status),
    );
    assert_eq!(
        method_mapping(ApiMethod::DestroySession)
            .and_then(|mapping| mapping.dispatch.fixed_session_command()),
        Some(SessionCommandKind::Stop),
    );
}

#[test]
fn representative_session_commands_round_trip_through_existing_session_set() {
    for mapping in API_COMMAND_MAPPINGS {
        let Some(command) = mapping.command_kind.representative_command() else {
            continue;
        };
        assert_eq!(SessionCommandKind::from(&command), mapping.command_kind);
    }
}

#[test]
fn control_and_send_dispatch_one_session_command_per_envelope() {
    assert_eq!(
        method_mapping(ApiMethod::Control)
            .and_then(|mapping| mapping.dispatch.command_cardinality()),
        Some(CommandDispatchCardinality::OneSessionCommandPerEnvelope),
    );
    assert_eq!(
        method_mapping(ApiMethod::Send).and_then(|mapping| mapping.dispatch.command_cardinality()),
        Some(CommandDispatchCardinality::OneSessionCommandPerEnvelope),
    );
    assert_eq!(
        method_mapping(ApiMethod::Watch).map(|mapping| mapping.dispatch),
        Some(ApiDispatch::WatchStream {
            attach_query: LiveQueryKind::Status,
        }),
    );
}
