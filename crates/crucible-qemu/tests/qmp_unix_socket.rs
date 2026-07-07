//! Checks Unix-domain socket connection helpers for typed QMP clients.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
#[cfg(target_os = "linux")]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use crucible_qemu::{
    QMP_CAPABILITIES_COMMAND, QMP_QUIT_COMMAND_NAME, QemuQmpVmStateControlChannel, QmpClient,
    QmpCommandKind,
};
#[cfg(target_os = "linux")]
use serde_json::Value;

#[cfg(target_os = "linux")]
#[test]
fn qmp_client_connects_and_negotiates_over_unix_socket() -> Result<(), Box<dyn Error>> {
    let socket = unique_socket_path("qmp-client")?;
    let listener = UnixListener::bind(&socket)?;
    let server = thread::spawn(move || qmp_server_accepts_capabilities(listener, true));

    let mut client = QmpClient::connect_unix_socket(&socket)?;
    assert_eq!(client.quit()?.command, QmpCommandKind::Quit);

    let request = join_server(server)?;
    assert_eq!(
        request.get("execute").and_then(Value::as_str),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    cleanup_socket_path(socket);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn vmstate_control_connects_over_unix_socket() -> Result<(), Box<dyn Error>> {
    let socket = unique_socket_path("qmp-vmstate")?;
    let listener = UnixListener::bind(&socket)?;
    let server = thread::spawn(move || qmp_server_accepts_capabilities(listener, false));

    let mut control = QemuQmpVmStateControlChannel::connect_unix_socket(&socket)?;
    assert_eq!(control.quit()?.command, QmpCommandKind::Quit);

    let request = join_server(server)?;
    assert_eq!(
        request.get("execute").and_then(Value::as_str),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    cleanup_socket_path(socket);
    Ok(())
}

#[cfg(target_os = "linux")]
fn qmp_server_accepts_capabilities(
    listener: UnixListener,
    expect_quit: bool,
) -> Result<Value, String> {
    let (stream, _addr) = listener.accept().map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream);
    reader
        .get_mut()
        .write_all(br#"{"QMP":{"version":{},"capabilities":[]}}"#)
        .and_then(|()| reader.get_mut().write_all(b"\r\n"))
        .and_then(|()| reader.get_mut().flush())
        .map_err(|error| error.to_string())?;

    let capabilities = read_qmp_line(&mut reader)?;
    reader
        .get_mut()
        .write_all(br#"{"return":{}}"#)
        .and_then(|()| reader.get_mut().write_all(b"\r\n"))
        .and_then(|()| reader.get_mut().flush())
        .map_err(|error| error.to_string())?;

    let quit = read_qmp_line(&mut reader)?;
    if expect_quit && quit.get("execute").and_then(Value::as_str) != Some(QMP_QUIT_COMMAND_NAME) {
        return Err(format!("expected QMP quit request, got {quit}"));
    }
    if !expect_quit && quit.get("execute").and_then(Value::as_str) != Some(QMP_QUIT_COMMAND_NAME) {
        return Err(format!("expected VMState control quit request, got {quit}"));
    }
    reader
        .get_mut()
        .write_all(br#"{"return":{}}"#)
        .and_then(|()| reader.get_mut().write_all(b"\r\n"))
        .and_then(|()| reader.get_mut().flush())
        .map_err(|error| error.to_string())?;

    Ok(capabilities)
}

#[cfg(target_os = "linux")]
fn read_qmp_line(reader: &mut BufReader<UnixStream>) -> Result<Value, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    serde_json::from_str(&line).map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn join_server(server: thread::JoinHandle<Result<Value, String>>) -> Result<Value, Box<dyn Error>> {
    match server.join() {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.into()),
        Err(_panic) => Err("QMP test server panicked".into()),
    }
}

#[cfg(target_os = "linux")]
fn unique_socket_path(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let mut dir = std::env::temp_dir();
    dir.push(format!("crucible-{label}-{}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir(&dir)?;
    Ok(dir.join("qmp.sock"))
}

#[cfg(target_os = "linux")]
fn cleanup_socket_path(socket: PathBuf) {
    if let Some(parent) = socket.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}
