//! Reverse conditions and local terminal relay support.

use super::*;

pub(crate) fn parse_debug_reverse_condition(value: &str) -> Result<crucible::Predicate, CliError> {
    if value == "quiescent" {
        return Ok(crucible::Predicate::quiescent());
    }
    if let Some(ticks) = value.strip_prefix("at:") {
        return Ok(crucible::Predicate::at(crucible::VirtualTime {
            ticks: parse_u64_value("reverse-continue at", ticks)?,
        }));
    }
    if let Some(encoded) = value.strip_prefix("hex:") {
        if !encoded.len().is_multiple_of(2) {
            return Err(usage_error(
                "reverse-continue hex condition has an odd number of digits",
            ));
        }
        let mut bytes = Vec::with_capacity(encoded.len() / 2);
        for pair in encoded.as_bytes().as_chunks::<2>().0 {
            let high = hex_nibble(pair[0]).ok_or_else(|| {
                usage_error("reverse-continue hex condition contains a non-hex digit")
            })?;
            let low = hex_nibble(pair[1]).ok_or_else(|| {
                usage_error("reverse-continue hex condition contains a non-hex digit")
            })?;
            bytes.push((high << 4) | low);
        }
        return crucible::Predicate::from_compact_binary(&bytes)
            .map_err(|error| usage_error(format!("invalid reverse-continue condition: {error}")));
    }
    Err(usage_error(
        "reverse-continue condition must be `quiescent`, `at:<ticks>`, or `hex:<compact-predicate>`",
    ))
}

pub(super) async fn run_remote_guest_fork(
    daemon: &str,
    backend_plan: &BackendSelectionPlan,
    session: SessionRef,
    node: crucible::NodeId,
) -> Result<(), CliError> {
    let client = remote_rpc_client(daemon, backend_plan)?;
    let acquisition = crucible_api::DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(session, &acquisition)
        .await
        .map_err(control_client_error)?;
    let fork_result = async {
        client
            .attach_debugger(session, &lease, &node)
            .await
            .map_err(control_client_error)?;
        client
            .fork_debug_guest_introspection(session, &lease, &node)
            .await
            .map_err(control_client_error)
    }
    .await;
    let release_result = client.release_debug_controller(session, &lease).await;
    let writable_branch = fork_result?;
    release_result.map_err(control_client_error)?;
    println!(
        "crucible: forked writable non-canonical branch={} argv-exec={} pty={} resize={} ssh-bridge={} max-channels={}",
        writable_branch
            .branch
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        writable_branch.features.argv_exec(),
        writable_branch.features.pty(),
        writable_branch.features.resize(),
        writable_branch.features.ssh_bridge(),
        writable_branch.features.max_channels(),
    );
    Ok(())
}

pub(super) async fn run_remote_debug_relay_async(
    daemon: &str,
    backend_plan: &BackendSelectionPlan,
    session: SessionRef,
    node: crucible::NodeId,
    gdb_listen: std::net::SocketAddr,
) -> Result<(), CliError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let client = remote_rpc_client(daemon, backend_plan)?;
    let acquisition = crucible_api::DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(session, &acquisition)
        .await
        .map_err(control_client_error)?;
    if let Err(error) = client.attach_debugger(session, &lease, &node).await {
        let _ = client.release_debug_controller(session, &lease).await;
        return Err(control_client_error(error));
    }
    let relay = match client.open_debug_relay(session, &lease).await {
        Ok(relay) => relay,
        Err(error) => {
            let _ = client.release_debug_controller(session, &lease).await;
            return Err(control_client_error(error));
        }
    };
    let listener = match tokio::net::TcpListener::bind(gdb_listen).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = client.close_debug_relay(session, &lease, relay).await;
            return Err(backend_error(format!(
                "cannot bind local GDB relay {gdb_listen}: {error}"
            )));
        }
    };
    let address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            let _ = client.close_debug_relay(session, &lease, relay).await;
            return Err(backend_error(format!(
                "cannot read local GDB relay address: {error}"
            )));
        }
    };
    println!("crucible: remote GDB relay listening at {address}");
    let accepted = tokio::select! {
        biased;
        accepted = listener.accept() => Some(accepted),
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => None,
                Err(error) => {
                    let _ = client.close_debug_relay(session, &lease, relay).await;
                    return Err(backend_error(format!("debug relay signal error: {error}")));
                }
            }
        }
    };
    let Some(accepted) = accepted else {
        let _ = client.close_debug_relay(session, &lease, relay).await;
        return Ok(());
    };
    let (mut local, _) = match accepted {
        Ok(accepted) => accepted,
        Err(error) => {
            let _ = client.close_debug_relay(session, &lease, relay).await;
            return Err(backend_error(format!(
                "cannot accept local GDB connection: {error}"
            )));
        }
    };
    let mut local_buffer = vec![0_u8; crucible_api::DEBUG_RELAY_CHUNK_MAX_BYTES];
    let mut poll = tokio::time::interval(Duration::from_millis(5));
    let relay_result: Result<(), CliError> = async {
        loop {
            tokio::select! {
            biased;
            read = local.read(&mut local_buffer) => {
                let length = read.map_err(|error| backend_error(format!("local GDB read failed: {error}")))?;
                if length == 0 {
                    break Ok(());
                }
                let written = client
                    .write_debug_relay(session, &lease, relay, &local_buffer[..length])
                    .await
                    .map_err(control_client_error)?;
                if written != length {
                    break Err(backend_error("remote GDB relay accepted a partial chunk"));
                }
            }
            _ = poll.tick() => {
                let chunk = client
                    .read_debug_relay(
                        session,
                        &lease,
                        relay,
                        crucible_api::DEBUG_RELAY_CHUNK_MAX_BYTES,
                    )
                    .await
                    .map_err(control_client_error)?;
                if !chunk.bytes.is_empty() {
                    local
                        .write_all(&chunk.bytes)
                        .await
                        .map_err(|error| backend_error(format!("local GDB write failed: {error}")))?;
                }
                if chunk.eof {
                    break Ok(());
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| backend_error(format!("debug relay signal error: {error}")))?;
                break Ok(());
            }
            }
        }
    }
    .await;
    let close_result = client.close_debug_relay(session, &lease, relay).await;
    relay_result?;
    close_result.map_err(control_client_error)?;
    Ok(())
}

pub(crate) const GUEST_TRANSCRIPT_HEADER: &[u8; 8] = b"CRGT\x01\0\0\0";
const GUEST_TRANSCRIPT_MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum GuestTranscriptDirection {
    HostToGuest = 1,
    GuestToHost = 2,
}

pub(crate) struct GuestTranscriptWriter {
    file: tokio::fs::File,
    bytes_written: u64,
}

impl GuestTranscriptWriter {
    pub(crate) async fn create(path: &Path) -> Result<Self, CliError> {
        use tokio::io::AsyncWriteExt as _;

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
            .map_err(|error| {
                backend_error(format!(
                    "cannot create guest transcript {}: {error}",
                    path.display()
                ))
            })?;
        file.write_all(GUEST_TRANSCRIPT_HEADER)
            .await
            .map_err(|error| backend_error(format!("cannot write guest transcript: {error}")))?;
        Ok(Self {
            file,
            bytes_written: GUEST_TRANSCRIPT_HEADER.len() as u64,
        })
    }

    pub(crate) async fn record(
        &mut self,
        direction: GuestTranscriptDirection,
        record: &crucible_api::GuestIntrospectionRecord,
    ) -> Result<(), CliError> {
        use tokio::io::AsyncWriteExt as _;

        let encoded = record
            .encode()
            .map_err(|error| backend_error(format!("cannot encode guest transcript: {error}")))?;
        let length = u32::try_from(encoded.len())
            .map_err(|_| backend_error("guest transcript record exceeds u32 length"))?;
        let frame_len = 8_u64.saturating_add(u64::from(length));
        if self.bytes_written.saturating_add(frame_len) > GUEST_TRANSCRIPT_MAX_BYTES {
            return Err(backend_error(format!(
                "guest transcript exceeds the {}-byte recording limit",
                GUEST_TRANSCRIPT_MAX_BYTES
            )));
        }
        let mut header = [0_u8; 8];
        header[0] = direction as u8;
        header[4..].copy_from_slice(&length.to_le_bytes());
        self.file
            .write_all(&header)
            .await
            .map_err(|error| backend_error(format!("cannot write guest transcript: {error}")))?;
        self.file
            .write_all(&encoded)
            .await
            .map_err(|error| backend_error(format!("cannot write guest transcript: {error}")))?;
        self.bytes_written += frame_len;
        Ok(())
    }

    pub(crate) async fn finish(&mut self) -> Result<(), CliError> {
        use tokio::io::AsyncWriteExt as _;

        self.file
            .flush()
            .await
            .map_err(|error| backend_error(format!("cannot flush guest transcript: {error}")))
    }
}

async fn exchange_guest_record(
    client: &RpcControlClient,
    session: SessionRef,
    lease: &crucible_api::DebugControllerAccess,
    node: &crucible::NodeId,
    channel_id: u64,
    request: Option<&crucible_api::GuestIntrospectionRecord>,
    transcript: &mut Option<GuestTranscriptWriter>,
) -> Result<Option<crucible_api::GuestIntrospectionRecord>, CliError> {
    let response = client
        .exchange_guest_introspection(session, lease, node, channel_id, request)
        .await
        .map_err(control_client_error)?;
    if let (Some(writer), Some(record)) = (transcript.as_mut(), request) {
        writer
            .record(GuestTranscriptDirection::HostToGuest, record)
            .await?;
    }
    if let (Some(writer), Some(record)) = (transcript.as_mut(), response.as_ref()) {
        writer
            .record(GuestTranscriptDirection::GuestToHost, record)
            .await?;
    }
    Ok(response)
}

pub(super) struct RemoteGuestChannelRequest<'a> {
    pub(super) daemon: &'a str,
    pub(super) backend_plan: &'a BackendSelectionPlan,
    pub(super) session: SessionRef,
    pub(super) node: crucible::NodeId,
    pub(super) open: crucible_api::GuestIntrospectionMessage,
    pub(super) interactive: bool,
    pub(super) transcript_path: Option<&'a Path>,
    pub(super) guest_idle_timeout: Duration,
}

pub(super) async fn run_remote_guest_channel(
    request: RemoteGuestChannelRequest<'_>,
) -> Result<(), CliError> {
    let RemoteGuestChannelRequest {
        daemon,
        backend_plan,
        session,
        node,
        open,
        interactive,
        transcript_path,
        guest_idle_timeout,
    } = request;
    use crucible_api::{GuestIntrospectionMessage, GuestIntrospectionRecord, GuestOutputStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pty_channel = matches!(&open, GuestIntrospectionMessage::Pty { .. });
    let _terminal_mode = LocalTerminalMode::enter_raw(interactive)?;
    let mut resize_signal = local_resize_signal(interactive)?;
    let mut transcript = match transcript_path {
        Some(path) => Some(GuestTranscriptWriter::create(path).await?),
        None => None,
    };
    let client = remote_rpc_client(daemon, backend_plan)?;
    let acquisition = crucible_api::DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(session, &acquisition)
        .await
        .map_err(control_client_error)?;
    let channel_id = lease.guest_channel_id();
    let open = GuestIntrospectionRecord::new(channel_id, open)
        .map_err(|error| backend_error(error.to_string()))?;
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut terminate_signal = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )
    .map_err(|error| backend_error(format!("guest channel termination signal error: {error}")))?;
    let mut hangup_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|error| backend_error(format!("guest channel hangup signal error: {error}")))?;
    let mut input_closed = !interactive;
    let mut terminal_observed = false;
    let channel_result: Result<(), CliError> = async {
        let response = exchange_guest_record(
            &client,
            session,
            &lease,
            &node,
            channel_id,
            Some(&open),
            &mut transcript,
        )
        .await?;
        if handle_guest_channel_response(
            response.as_ref(),
            channel_id,
            &mut stdout,
            &mut stderr,
            &mut terminal_observed,
        )
        .await?
            == GuestChannelRecordOutcome::Exit
        {
            return Ok(());
        }
        if !interactive {
            let close = GuestIntrospectionRecord::new(
                channel_id,
                GuestIntrospectionMessage::Close,
            )
            .map_err(|error| backend_error(error.to_string()))?;
            let response = exchange_guest_record(
                &client,
                session,
                &lease,
                &node,
                channel_id,
                Some(&close),
                &mut transcript,
            )
            .await?;
            if handle_guest_channel_response(
                response.as_ref(),
                channel_id,
                &mut stdout,
                &mut stderr,
                &mut terminal_observed,
            )
            .await?
                == GuestChannelRecordOutcome::Exit
            {
                return Ok(());
            }
        }
        let mut input = vec![0_u8; 4096];
        let mut poll = tokio::time::interval(Duration::from_millis(5));
        let mut idle_deadline = tokio::time::interval(guest_idle_timeout);
        idle_deadline.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        idle_deadline.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = idle_deadline.tick() => {
                    break Err(backend_error(format!(
                        "guest agent produced no response for {} ms; verify that the non-canonical fork activated `crucible-guest agent` or increase --guest-idle-timeout",
                        guest_idle_timeout.as_millis()
                    )));
                }
                signal = receive_guest_channel_shutdown_signal(
                    &mut terminate_signal,
                    &mut hangup_signal,
                ) => {
                    signal?;
                    let close = GuestIntrospectionRecord::new(
                        channel_id,
                        GuestIntrospectionMessage::Close,
                    )
                    .map_err(|error| backend_error(error.to_string()))?;
                    let response = exchange_guest_record(
                        &client,
                        session,
                        &lease,
                        &node,
                        channel_id,
                        Some(&close),
                        &mut transcript,
                    )
                    .await?;
                    handle_guest_channel_shutdown_response(
                        response.as_ref(),
                        channel_id,
                        &mut stdout,
                        &mut stderr,
                        &mut terminal_observed,
                    )
                    .await?;
                    break Ok(());
                }
                read = stdin.read(&mut input), if !input_closed => {
                    let length = read.map_err(|error| backend_error(format!("terminal input failed: {error}")))?;
                    let message = guest_input_message(pty_channel, &input[..length]);
                    let record = GuestIntrospectionRecord::new(channel_id, message)
                        .map_err(|error| backend_error(error.to_string()))?;
                    let response = exchange_guest_record(
                        &client,
                        session,
                        &lease,
                        &node,
                        channel_id,
                        Some(&record),
                        &mut transcript,
                    )
                    .await?;
                    if handle_guest_channel_response(
                        response.as_ref(),
                        channel_id,
                        &mut stdout,
                        &mut stderr,
                        &mut terminal_observed,
                    )
                    .await?
                        == GuestChannelRecordOutcome::Exit
                    {
                        break Ok(());
                    }
                    if length == 0 {
                        input_closed = true;
                    }
                }
                _ = poll.tick() => {
                    let Some(record) = exchange_guest_record(
                        &client,
                        session,
                        &lease,
                        &node,
                        channel_id,
                        None,
                        &mut transcript,
                    )
                    .await?
                    else {
                        continue;
                    };
                    idle_deadline.reset();
                    if handle_guest_channel_response(
                        Some(&record),
                        channel_id,
                        &mut stdout,
                        &mut stderr,
                        &mut terminal_observed,
                    )
                    .await?
                        == GuestChannelRecordOutcome::Exit
                    {
                        break Ok(());
                    }
                }
                resized = receive_local_resize(&mut resize_signal), if resize_signal.is_some() => {
                    if resized {
                        let (columns, rows) = local_terminal_size()?;
                        let record = GuestIntrospectionRecord::new(
                            channel_id,
                            GuestIntrospectionMessage::Resize { columns, rows },
                        )
                        .map_err(|error| backend_error(error.to_string()))?;
                        let response = exchange_guest_record(
                            &client,
                            session,
                            &lease,
                            &node,
                            channel_id,
                            Some(&record),
                            &mut transcript,
                        )
                        .await?;
                        if handle_guest_channel_response(
                            response.as_ref(),
                            channel_id,
                            &mut stdout,
                            &mut stderr,
                            &mut terminal_observed,
                        )
                        .await?
                            == GuestChannelRecordOutcome::Exit
                        {
                            break Ok(());
                        }
                    }
                }
            }
        }
    }
    .await;
    let cleanup_result: Result<(), CliError> = async {
        if terminal_observed {
            return Ok(());
        }
        let close = GuestIntrospectionRecord::new(channel_id, GuestIntrospectionMessage::Close)
            .map_err(|error| backend_error(error.to_string()))?;
        let _response = exchange_guest_record(
            &client,
            session,
            &lease,
            &node,
            channel_id,
            Some(&close),
            &mut transcript,
        )
        .await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = exchange_guest_record(
                    &client,
                    session,
                    &lease,
                    &node,
                    channel_id,
                    None,
                    &mut transcript,
                )
                .await?;
                match response.as_ref().map(GuestIntrospectionRecord::message) {
                    Some(GuestIntrospectionMessage::Output { stream, bytes }) => {
                        match stream {
                            GuestOutputStream::Stdout => stdout.write_all(bytes).await,
                            GuestOutputStream::Stderr => stderr.write_all(bytes).await,
                        }
                        .map_err(|error| {
                            backend_error(format!("terminal cleanup output failed: {error}"))
                        })?;
                        match stream {
                            GuestOutputStream::Stdout => stdout.flush().await,
                            GuestOutputStream::Stderr => stderr.flush().await,
                        }
                        .map_err(|error| {
                            backend_error(format!("terminal cleanup output flush failed: {error}"))
                        })?;
                    }
                    Some(
                        GuestIntrospectionMessage::Exit { .. }
                        | GuestIntrospectionMessage::Error { .. },
                    ) => break Ok(()),
                    Some(_) | None => tokio::time::sleep(Duration::from_millis(5)).await,
                }
            }
        })
        .await
        .map_err(|_| backend_error("timed out closing guest-introspection channel"))?
    }
    .await;
    let transcript_result = match transcript.as_mut() {
        Some(transcript) => transcript.finish().await,
        None => Ok(()),
    };
    let release_result = client.release_debug_controller(session, &lease).await;
    if let Err(error) = channel_result {
        let _cleanup = cleanup_result;
        let _transcript = transcript_result;
        let _release = release_result;
        return Err(error);
    }
    cleanup_result?;
    transcript_result?;
    release_result.map_err(control_client_error)?;
    Ok(())
}

struct LocalTerminalMode {
    original: Option<rustix::termios::Termios>,
}

impl LocalTerminalMode {
    fn enter_raw(enabled: bool) -> Result<Self, CliError> {
        use std::io::IsTerminal;

        if !enabled || !std::io::stdin().is_terminal() {
            return Ok(Self { original: None });
        }
        let original = rustix::termios::tcgetattr(std::io::stdin())
            .map_err(|error| backend_error(format!("cannot read local terminal mode: {error}")))?;
        let mut raw = original.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Now,
            &raw,
        )
        .map_err(|error| backend_error(format!("cannot enter local terminal raw mode: {error}")))?;
        Ok(Self {
            original: Some(original),
        })
    }
}

impl Drop for LocalTerminalMode {
    fn drop(&mut self) {
        if let Some(original) = self.original.as_ref() {
            let _restored = rustix::termios::tcsetattr(
                std::io::stdin(),
                rustix::termios::OptionalActions::Now,
                original,
            );
        }
    }
}

fn local_resize_signal(enabled: bool) -> Result<Option<tokio::signal::unix::Signal>, CliError> {
    use std::io::IsTerminal;

    if !enabled || !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .map(Some)
        .map_err(|error| backend_error(format!("cannot monitor local terminal resize: {error}")))
}

async fn receive_local_resize(signal: &mut Option<tokio::signal::unix::Signal>) -> bool {
    match signal {
        Some(signal) => signal.recv().await.is_some(),
        None => std::future::pending().await,
    }
}

fn local_terminal_size() -> Result<(u16, u16), CliError> {
    let size = rustix::termios::tcgetwinsize(std::io::stdin())
        .map_err(|error| backend_error(format!("cannot read local terminal size: {error}")))?;
    if size.ws_col == 0 || size.ws_row == 0 {
        return Err(backend_error("local terminal reported a zero window size"));
    }
    Ok((size.ws_col, size.ws_row))
}

pub(super) fn parse_debug_session_ref(value: &str) -> Result<SessionRef, CliError> {
    let mut fields = value.split(':');
    let id = parse_u64_value("--session id", fields.next().unwrap_or_default())?;
    let epoch = parse_u64_value("--session epoch", fields.next().unwrap_or_default())?;
    let seed_text = fields.next().unwrap_or_default();
    if fields.next().is_some() || seed_text.len() != 64 {
        return Err(usage_error(
            "--session must use id:epoch:64-lowercase-hex-seed",
        ));
    }
    let mut seed = [0_u8; 32];
    for (index, chunk) in seed_text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| usage_error("--session seed must be lowercase hexadecimal"))?;
        if pair.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(usage_error("--session seed must be lowercase hexadecimal"));
        }
        seed[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| usage_error("--session seed must be lowercase hexadecimal"))?;
    }
    Ok(SessionRef::new(
        crucible_api::SessionId::new(id),
        epoch,
        crucible::Seed::from_bytes(seed),
    ))
}

#[cfg(test)]
mod remote_debug_tests {
    use super::*;

    #[test]
    fn remote_session_reference_requires_canonical_complete_identity() {
        let parsed = parse_debug_session_ref(
            "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap_or_else(|error| panic!("canonical session reference should parse: {error}"));
        assert_eq!(parsed.id.value, 7);
        assert_eq!(parsed.epoch, 12);

        assert!(parse_debug_session_ref("7:12:abcd").is_err());
        assert!(
            parse_debug_session_ref(
                "7:12:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .is_err()
        );
        assert!(
            parse_debug_session_ref(
                "7:12:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:extra"
            )
            .is_err()
        );
    }
}
