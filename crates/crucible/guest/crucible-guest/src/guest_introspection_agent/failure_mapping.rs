//! Guest-agent protocol and process error classification.

use super::*;

pub(super) fn process_missing(stream: &'static str) -> GuestIntrospectionAgentError {
    GuestIntrospectionAgentError::Process {
        message: format!("spawned guest process did not expose {stream}"),
    }
}

pub(super) fn process_error(
    operation: &'static str,
    error: std::io::Error,
) -> GuestIntrospectionAgentError {
    GuestIntrospectionAgentError::Process {
        message: format!("{operation}: {error}"),
    }
}

pub(super) fn protocol_error(error: impl ToString) -> GuestIntrospectionAgentError {
    GuestIntrospectionAgentError::Protocol {
        message: error.to_string(),
    }
}

pub(super) fn channel_error_code(
    error: &GuestIntrospectionAgentError,
    opening_request: bool,
) -> GuestIntrospectionFailureCode {
    match error {
        GuestIntrospectionAgentError::DuplicateChannel { .. } => {
            GuestIntrospectionFailureCode::DuplicateChannel
        }
        GuestIntrospectionAgentError::UnknownChannel { .. } => {
            GuestIntrospectionFailureCode::UnknownChannel
        }
        GuestIntrospectionAgentError::ChannelLimit { .. } => {
            GuestIntrospectionFailureCode::ChannelLimit
        }
        GuestIntrospectionAgentError::ClosedChannel { .. } => {
            GuestIntrospectionFailureCode::ClosedChannel
        }
        GuestIntrospectionAgentError::NotPty { .. } => GuestIntrospectionFailureCode::NotPty,
        GuestIntrospectionAgentError::Unsupported { .. } => {
            GuestIntrospectionFailureCode::Unsupported
        }
        GuestIntrospectionAgentError::Process { .. } if opening_request => {
            GuestIntrospectionFailureCode::OpenFailed
        }
        GuestIntrospectionAgentError::Configuration { .. }
        | GuestIntrospectionAgentError::Protocol { .. }
        | GuestIntrospectionAgentError::Doorbell(_)
        | GuestIntrospectionAgentError::Process { .. }
        | GuestIntrospectionAgentError::ReaderPanic { .. } => {
            GuestIntrospectionFailureCode::ProcessIo
        }
    }
}

pub(super) fn bounded_error_message(error: &GuestIntrospectionAgentError) -> String {
    let mut message = error.to_string();
    while message.len() > GUEST_INTROSPECTION_MAX_ERROR_BYTES {
        message.pop();
    }
    message
}
