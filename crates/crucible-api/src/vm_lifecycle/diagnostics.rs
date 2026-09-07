//! Cause-preserving diagnostics at the lifecycle's string-error boundary.
//!
//! Backend errors retain typed sources internally. The lifecycle API currently
//! stores loop-construction errors as text, so it must render the complete
//! source chain before that conversion loses the underlying launch failure.

use std::error::Error;

pub(super) fn error_chain(error: &impl Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("assemble node")]
    struct LaunchError {
        source: ConnectError,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("connect control channel")]
    struct ConnectError {
        source: std::io::Error,
    }

    #[test]
    fn launch_diagnostic_retains_all_underlying_causes() {
        let error = LaunchError {
            source: ConnectError {
                source: std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake expired"),
            },
        };
        assert_eq!(
            error_chain(&error),
            "assemble node: connect control channel: handshake expired",
        );
    }

    #[test]
    fn leaf_diagnostic_has_no_empty_cause_suffix() {
        let error = std::io::Error::other("invalid launch basis");
        assert_eq!(error_chain(&error), "invalid launch basis");
    }
}
