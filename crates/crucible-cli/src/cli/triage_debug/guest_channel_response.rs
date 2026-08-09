//! Guest-introspection response handling for the remote debugger CLI.

use super::*;
// crucible-lint: allow host-nondeterminism-state -- these typed records remain guest transport and never enter scheduler state.
use crucible_api::{
    GuestIntrospectionFailureCode, GuestIntrospectionMessage, GuestIntrospectionRecord,
    GuestOutputStream,
};

pub(super) async fn receive_guest_channel_shutdown_signal(
    terminate: &mut tokio::signal::unix::Signal,
    hangup: &mut tokio::signal::unix::Signal,
) -> Result<(), CliError> {
    tokio::select! {
        biased;
        signal = tokio::signal::ctrl_c() => signal
            .map_err(|error| backend_error(format!("guest channel interrupt signal error: {error}"))),
        signal = terminate.recv() => signal
            .ok_or_else(|| backend_error("guest channel termination signal stream closed")),
        signal = hangup.recv() => signal
            .ok_or_else(|| backend_error("guest channel hangup signal stream closed")),
    }
}

/// Converts local input into the guest channel's stream semantics.
// crucible-lint: allow host-nondeterminism-state -- this public helper performs only pure guest-transport conversion.
pub(crate) fn guest_input_message(
    pty_channel: bool,
    input: &[u8],
    // crucible-lint: allow host-nondeterminism-state -- this pure conversion produces only guest-channel transport input.
) -> GuestIntrospectionMessage {
    if !input.is_empty() {
        return GuestIntrospectionMessage::Input(input.to_vec());
    }
    if pty_channel {
        // Closing a PTY input descriptor is a hangup. EOT supplies ordinary
        // terminal EOF without killing a command that is still draining output.
        GuestIntrospectionMessage::Input(vec![0x04])
    } else {
        GuestIntrospectionMessage::Close
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuestChannelRecordOutcome {
    Continue,
    Exit,
}

pub(super) async fn handle_guest_channel_response(
    response: Option<&GuestIntrospectionRecord>,
    channel_id: u64,
    stdout: &mut tokio::io::Stdout,
    stderr: &mut tokio::io::Stderr,
    terminal_observed: &mut bool,
) -> Result<GuestChannelRecordOutcome, CliError> {
    use tokio::io::AsyncWriteExt as _;

    let Some(record) = response else {
        return Ok(GuestChannelRecordOutcome::Continue);
    };
    if record.channel_id() != channel_id {
        return Ok(GuestChannelRecordOutcome::Continue);
    }

    match record.message() {
        GuestIntrospectionMessage::Output { stream, bytes } => {
            match stream {
                GuestOutputStream::Stdout => stdout.write_all(bytes).await,
                GuestOutputStream::Stderr => stderr.write_all(bytes).await,
            }
            .map_err(|error| backend_error(format!("terminal output failed: {error}")))?;
            match stream {
                GuestOutputStream::Stdout => stdout.flush().await,
                GuestOutputStream::Stderr => stderr.flush().await,
            }
            .map_err(|error| backend_error(format!("terminal output flush failed: {error}")))?;
            Ok(GuestChannelRecordOutcome::Continue)
        }
        GuestIntrospectionMessage::Exit { status, signal } => {
            *terminal_observed = true;
            stdout
                .flush()
                .await
                .map_err(|error| backend_error(error.to_string()))?;
            stderr
                .flush()
                .await
                .map_err(|error| backend_error(error.to_string()))?;
            if *status == 0 {
                return Ok(GuestChannelRecordOutcome::Exit);
            }
            Err(backend_error(format!(
                "guest command exited with status {status} signal {signal:?}"
            )))
        }
        GuestIntrospectionMessage::Error { code, message } => {
            *terminal_observed = true;
            Err(backend_error(guest_failure_diagnostic(*code, message)))
        }
        GuestIntrospectionMessage::Features(_)
        | GuestIntrospectionMessage::Exec { .. }
        | GuestIntrospectionMessage::Pty { .. }
        | GuestIntrospectionMessage::Ssh { .. }
        | GuestIntrospectionMessage::Input(_)
        | GuestIntrospectionMessage::Resize { .. }
        | GuestIntrospectionMessage::Close => Err(backend_error(
            "guest agent returned an unexpected protocol record",
        )),
    }
}

/// Consumes a response returned while locally shutting down a guest channel.
///
/// Exit and error records confirm requested shutdown rather than reporting a
/// failed guest command to the proxy's caller.
///
/// # Errors
///
/// Returns [`CliError`] when a nonterminal response cannot be written or is
/// invalid for the guest-channel protocol state.
pub(super) async fn handle_guest_channel_shutdown_response(
    response: Option<&GuestIntrospectionRecord>,
    channel_id: u64,
    stdout: &mut tokio::io::Stdout,
    stderr: &mut tokio::io::Stderr,
    terminal_observed: &mut bool,
) -> Result<(), CliError> {
    match response.map(GuestIntrospectionRecord::message) {
        Some(GuestIntrospectionMessage::Exit { .. } | GuestIntrospectionMessage::Error { .. })
            if response.is_some_and(|record| record.channel_id() == channel_id) =>
        {
            *terminal_observed = true;
            Ok(())
        }
        Some(_) => {
            let _outcome = handle_guest_channel_response(
                response,
                channel_id,
                stdout,
                stderr,
                terminal_observed,
            )
            .await?;
            Ok(())
        }
        None => Ok(()),
    }
}

fn guest_failure_diagnostic(code: GuestIntrospectionFailureCode, message: &str) -> String {
    if code == GuestIntrospectionFailureCode::ClosedChannel {
        return format!("guest channel closed ({code:?}): {message}");
    }
    format!("guest introspection failed ({code:?}): {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reposition_closure_is_not_described_as_an_introspection_failure() {
        let diagnostic = guest_failure_diagnostic(
            GuestIntrospectionFailureCode::ClosedChannel,
            "debug runtime reposition closed the guest channel",
        );

        assert_eq!(
            diagnostic,
            "guest channel closed (ClosedChannel): debug runtime reposition closed the guest channel"
        );
    }

    #[tokio::test]
    async fn requested_shutdown_accepts_a_terminal_guest_response() {
        let response = GuestIntrospectionRecord::new(
            7,
            GuestIntrospectionMessage::Error {
                code: GuestIntrospectionFailureCode::ClosedChannel,
                message: String::from("channel terminated after local hangup"),
            },
        )
        .unwrap_or_else(|error| panic!("terminal response should encode: {error}"));
        let mut terminal_observed = false;

        handle_guest_channel_shutdown_response(
            Some(&response),
            7,
            &mut tokio::io::stdout(),
            &mut tokio::io::stderr(),
            &mut terminal_observed,
        )
        .await
        .unwrap_or_else(|error| panic!("requested shutdown should accept terminal reply: {error}"));

        assert!(terminal_observed);
    }
}
