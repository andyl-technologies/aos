//! Guest-introspection response handling for the remote debugger CLI.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuestChannelRecordOutcome {
    Continue,
    Exit,
}

pub(super) async fn handle_guest_channel_response(
    response: Option<&crucible_api::GuestIntrospectionRecord>,
    channel_id: u64,
    stdout: &mut tokio::io::Stdout,
    stderr: &mut tokio::io::Stderr,
    terminal_observed: &mut bool,
) -> Result<GuestChannelRecordOutcome, CliError> {
    use crucible_api::{GuestIntrospectionMessage, GuestOutputStream};
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
            Err(backend_error(format!(
                "guest introspection failed ({code:?}): {message}"
            )))
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
