//! Checks Unix-domain socket connection helpers for typed QMP clients.

#![deny(unsafe_op_in_unsafe_fn)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use crucible_qemu::{
    QMP_CAPABILITIES_COMMAND, QMP_CLOSEFD_COMMAND, QMP_GETFD_COMMAND,
    QMP_HOT_FORK_PLUGIN_ENDPOINTS_COMMAND, QMP_HOT_FORK_PRIVATE_RINGS_COMMAND,
    QMP_QUIT_COMMAND_NAME, QemuQmpVmStateControlChannel, QmpClient, QmpCommandKind,
    QmpDescriptorName, QmpError, QmpHotForkPluginEndpointIdentity,
};
#[cfg(target_os = "linux")]
use crucible_shmem::mmap_setup_region;
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
#[test]
fn qmp_getfd_transfers_one_exact_descriptor_and_closefd_releases_name() -> Result<(), Box<dyn Error>>
{
    let (client_stream, server_stream) = UnixStream::pair()?;
    let source = tempfile::tempfile()?;
    source.set_len(4096)?;
    let source_metadata = source.metadata()?;
    let server = thread::spawn(move || -> Result<(Value, Value, fs::Metadata), String> {
        let stream = negotiate_qmp(server_stream)?;
        let (getfd, descriptor) = receive_qmp_descriptor_request(&stream)?;
        let received_metadata = fs::File::from(descriptor)
            .metadata()
            .map_err(|error| error.to_string())?;
        write_qmp_return(&stream, b"{\"return\":{}}\r\n")?;

        let mut reader = BufReader::new(stream);
        let closefd = read_qmp_line(&mut reader)?;
        write_qmp_return(reader.get_ref(), b"{\"return\":{}}\r\n")?;
        Ok((getfd, closefd, received_metadata))
    });

    let mut client = QmpClient::connect(client_stream)?;
    let name = QmpDescriptorName::new("crucible-hfork-rings-v1-test")?;
    assert_eq!(
        client.install_descriptor(&name, source.as_fd())?.command,
        QmpCommandKind::GetFd
    );
    assert_eq!(
        client.close_descriptor(&name)?.command,
        QmpCommandKind::CloseFd
    );

    let (getfd, closefd, received_metadata) = join_server(server)?;
    assert_eq!(
        getfd.get("exec-oob").and_then(Value::as_str),
        Some(QMP_GETFD_COMMAND)
    );
    assert_eq!(
        getfd.pointer("/arguments/fdname").and_then(Value::as_str),
        Some(name.as_str())
    );
    assert_eq!(
        closefd.get("exec-oob").and_then(Value::as_str),
        Some(QMP_CLOSEFD_COMMAND)
    );
    assert_eq!(
        closefd.pointer("/arguments/fdname").and_then(Value::as_str),
        Some(name.as_str())
    );
    assert_eq!(received_metadata.len(), source_metadata.len());
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(received_metadata.dev(), source_metadata.dev());
    assert_eq!(received_metadata.ino(), source_metadata.ino());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn qmp_getfd_rejection_poisons_connection_and_preserves_caller_descriptor()
-> Result<(), Box<dyn Error>> {
    let (client_stream, server_stream) = UnixStream::pair()?;
    let source = tempfile::tempfile()?;
    source.set_len(127)?;
    let server = thread::spawn(move || -> Result<(), String> {
        let stream = negotiate_qmp(server_stream)?;
        let (_getfd, descriptor) = receive_qmp_descriptor_request(&stream)?;
        drop(descriptor);
        write_qmp_return(
            &stream,
            b"{\"error\":{\"class\":\"GenericError\",\"desc\":\"injected getfd failure\"}}\r\n",
        )?;
        let mut byte = [0u8; 1];
        match std::io::Read::read(&mut &stream, &mut byte) {
            Ok(0) => Ok(()),
            Ok(count) => Err(format!("poisoned QMP peer received {count} extra bytes")),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.to_string()),
        }
    });

    let mut client = QmpClient::connect(client_stream)?;
    let name = QmpDescriptorName::new("crucible-hfork-rings-v1-rejected")?;
    assert!(matches!(
        client.install_descriptor(&name, source.as_fd()),
        Err(QmpError::Command {
            command: QmpCommandKind::GetFd,
            ..
        })
    ));
    assert_eq!(source.metadata()?.len(), 127);
    assert_eq!(client.quit(), Err(QmpError::ConnectionPoisoned));
    join_server(server)?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn vmstate_control_stages_and_releases_both_descriptor_ownership_layers()
-> Result<(), Box<dyn Error>> {
    let (client_stream, server_stream) = UnixStream::pair()?;
    let source = tempfile::tempfile()?;
    source.set_len(4096)?;
    let mapping = mmap_setup_region(source.as_fd(), 4096)?;
    let identity = mapping.backing_identity();
    let name = QmpDescriptorName::new("crucible-hfork-rings-v1-owned")?;
    let expected_name = name.clone();
    let server = thread::spawn(move || -> Result<Vec<Value>, String> {
        let stream = negotiate_qmp(server_stream)?;
        let (getfd, descriptor) = receive_qmp_descriptor_request(&stream)?;
        let metadata = fs::File::from(descriptor)
            .metadata()
            .map_err(|error| error.to_string())?;
        use std::os::unix::fs::MetadataExt as _;
        if metadata.dev() != identity.device()
            || metadata.ino() != identity.inode()
            || metadata.len() != identity.length()
        {
            return Err(String::from("transferred descriptor identity changed"));
        }
        write_qmp_return(&stream, b"{\"return\":{}}\r\n")?;

        let mut reader = BufReader::new(stream);
        let stage = read_qmp_line(&mut reader)?;
        let stage_response = format!(
            concat!(
                r#"{{"return":{{"schema-version":3,"generation":1,"template-generation":0,"staged":true,"fdname":"{}","device":{},"inode":{},"length":{},"shrink-sealed":true,"source-mapping-bound":false,"source-start":0,"source-length":0,"source-offset":0,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#,
                "\r\n"
            ),
            expected_name.as_str(),
            identity.device(),
            identity.inode(),
            identity.length(),
        );
        write_qmp_return(reader.get_ref(), stage_response.as_bytes())?;

        let release = read_qmp_line(&mut reader)?;
        write_qmp_return(
            reader.get_ref(),
            b"{\"return\":{\"schema-version\":3,\"generation\":2,\"template-generation\":0,\"staged\":false,\"device\":0,\"inode\":0,\"length\":0,\"shrink-sealed\":false,\"source-mapping-bound\":false,\"source-start\":0,\"source-length\":0,\"source-offset\":0,\"disposition-complete\":false,\"readiness-proof-acknowledged\":false}}\r\n",
        )?;
        let closefd = read_qmp_line(&mut reader)?;
        write_qmp_return(reader.get_ref(), b"{\"return\":{}}\r\n")?;
        Ok(vec![getfd, stage, release, closefd])
    });

    let mut control = QemuQmpVmStateControlChannel::new(QmpClient::connect(client_stream)?);
    control.install_hot_fork_private_ring_descriptor(&name, source.as_fd(), identity)?;
    control.close_hot_fork_private_ring_descriptor(&name, identity)?;

    let requests = join_server(server)?;
    assert_eq!(
        requests[0].get("exec-oob").and_then(Value::as_str),
        Some(QMP_GETFD_COMMAND)
    );
    assert_eq!(
        requests[1].get("exec-oob").and_then(Value::as_str),
        Some(QMP_HOT_FORK_PRIVATE_RINGS_COMMAND)
    );
    assert_eq!(
        requests[1]
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("stage")
    );
    assert_eq!(
        requests[2]
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("release")
    );
    assert_eq!(
        requests[3].get("exec-oob").and_then(Value::as_str),
        Some(QMP_CLOSEFD_COMMAND)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn vmstate_control_orders_both_plugin_endpoint_ownership_layers() -> Result<(), Box<dyn Error>> {
    let (client_stream, server_stream) = UnixStream::pair()?;
    let control_source = tempfile::tempfile()?;
    let wake_source = tempfile::tempfile()?;
    let control_name = QmpDescriptorName::new("crucible-hfork-control-v1-owned")?;
    let wake_name = QmpDescriptorName::new("crucible-hfork-wake-v1-owned")?;
    let identity = QmpHotForkPluginEndpointIdentity::new(101, 202)
        .ok_or("nonzero endpoint identity should be valid")?;
    let expected_control_name = control_name.clone();
    let expected_wake_name = wake_name.clone();
    let server = thread::spawn(move || -> Result<Vec<Value>, String> {
        let stream = negotiate_qmp(server_stream)?;
        let (control_getfd, control_descriptor) = receive_qmp_descriptor_request(&stream)?;
        drop(control_descriptor);
        write_qmp_return(&stream, b"{\"return\":{}}\r\n")?;

        let (wake_getfd, wake_descriptor) = receive_qmp_descriptor_request(&stream)?;
        drop(wake_descriptor);
        write_qmp_return(&stream, b"{\"return\":{}}\r\n")?;

        let mut reader = BufReader::new(stream);
        let stage = read_qmp_line(&mut reader)?;
        let stage_response = format!(
            concat!(
                r#"{{"return":{{"schema-version":4,"generation":1,"template-generation":0,"staged":true,"control-fdname":"{}","wake-fdname":"{}","control-socket-cookie":101,"wake-eventfd-id":202,"control-source-fd":30,"wake-source-fd":31,"control-target-fd":-1,"wake-target-fd":-1,"private-ring-generation":7,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-planned":false,"replacement-plan-bound":false,"control-unix-stream":true,"wake-eventfd":true,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#,
                "\r\n"
            ),
            expected_control_name.as_str(),
            expected_wake_name.as_str(),
        );
        write_qmp_return(reader.get_ref(), stage_response.as_bytes())?;

        let release = read_qmp_line(&mut reader)?;
        write_qmp_return(
            reader.get_ref(),
            b"{\"return\":{\"schema-version\":4,\"generation\":2,\"template-generation\":0,\"staged\":false,\"control-socket-cookie\":0,\"wake-eventfd-id\":0,\"control-source-fd\":-1,\"wake-source-fd\":-1,\"control-target-fd\":-1,\"wake-target-fd\":-1,\"private-ring-generation\":0,\"plugin-barrier-generation\":0,\"worker-mask\":0,\"parent-resume-worker-mask\":0,\"child-reinitialize-worker-mask\":0,\"pending-worker-mask\":0,\"worker-disposition-planned\":false,\"replacement-plan-bound\":false,\"control-unix-stream\":false,\"wake-eventfd\":false,\"disposition-complete\":false,\"readiness-proof-acknowledged\":false}}\r\n",
        )?;
        let wake_closefd = read_qmp_line(&mut reader)?;
        write_qmp_return(reader.get_ref(), b"{\"return\":{}}\r\n")?;
        let control_closefd = read_qmp_line(&mut reader)?;
        write_qmp_return(reader.get_ref(), b"{\"return\":{}}\r\n")?;
        Ok(vec![
            control_getfd,
            wake_getfd,
            stage,
            release,
            wake_closefd,
            control_closefd,
        ])
    });

    let mut control = QemuQmpVmStateControlChannel::new(QmpClient::connect(client_stream)?);
    control.install_hot_fork_plugin_endpoints(
        &control_name,
        control_source.as_fd(),
        &wake_name,
        wake_source.as_fd(),
        identity,
        7,
    )?;
    control.close_hot_fork_plugin_endpoints(&control_name, &wake_name, identity)?;

    let requests = join_server(server)?;
    assert_eq!(
        requests[0].get("exec-oob").and_then(Value::as_str),
        Some(QMP_GETFD_COMMAND)
    );
    assert_eq!(
        requests[0]
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(control_name.as_str())
    );
    assert_eq!(
        requests[1].get("exec-oob").and_then(Value::as_str),
        Some(QMP_GETFD_COMMAND)
    );
    assert_eq!(
        requests[1]
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(wake_name.as_str())
    );
    assert_eq!(
        requests[2].get("exec-oob").and_then(Value::as_str),
        Some(QMP_HOT_FORK_PLUGIN_ENDPOINTS_COMMAND)
    );
    assert_eq!(
        requests[3]
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("release")
    );
    assert_eq!(
        requests[4]
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(wake_name.as_str())
    );
    assert_eq!(
        requests[5]
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(control_name.as_str())
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn qmp_descriptor_names_use_the_closed_bounded_grammar() {
    assert!(QmpDescriptorName::new("a").is_ok());
    assert!(QmpDescriptorName::new("crucible-hfork-rings-v1-0123456789").is_ok());
    assert!(QmpDescriptorName::new("").is_err());
    assert!(QmpDescriptorName::new("UPPER").is_err());
    assert!(QmpDescriptorName::new("slash/name").is_err());
    assert!(QmpDescriptorName::new("x".repeat(129)).is_err());
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
fn negotiate_qmp(mut stream: UnixStream) -> Result<UnixStream, String> {
    stream
        .write_all(b"{\"QMP\":{\"version\":{},\"capabilities\":[]}}\r\n")
        .and_then(|()| stream.flush())
        .map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream);
    let capabilities = read_qmp_line(&mut reader)?;
    if capabilities.get("execute").and_then(Value::as_str) != Some(QMP_CAPABILITIES_COMMAND) {
        return Err(format!(
            "expected QMP capabilities request, got {capabilities}"
        ));
    }
    write_qmp_return(reader.get_ref(), b"{\"return\":{}}\r\n")?;
    Ok(reader.into_inner())
}

#[cfg(target_os = "linux")]
fn write_qmp_return(stream: &UnixStream, bytes: &[u8]) -> Result<(), String> {
    let mut stream = stream;
    stream
        .write_all(bytes)
        .and_then(|()| stream.flush())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn receive_qmp_descriptor_request(stream: &UnixStream) -> Result<(Value, OwnedFd), String> {
    let mut bytes = [0u8; 4096];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: bytes.len(),
    };
    let mut control = [empty_control_header(); 2];
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: std::mem::size_of_val(&control),
        msg_flags: 0,
    };
    // SAFETY: all msghdr pointers reference live writable buffers for this call.
    let received = unsafe {
        libc::recvmsg(
            stream.as_fd().as_raw_fd(),
            &mut message,
            libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(String::from("QMP descriptor ancillary data was truncated"));
    }
    let received = usize::try_from(received).map_err(|error| error.to_string())?;
    let request = serde_json::from_slice::<Value>(&bytes[..received])
        .map_err(|error| format!("decode descriptor-bearing QMP request: {error}"))?;

    // SAFETY: `message` still references the live aligned ancillary buffer.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(String::from("QMP descriptor request omitted SCM_RIGHTS"));
    }
    // SAFETY: `header` was returned for this live message and holds one RawFd.
    let descriptor = unsafe {
        if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
            return Err(String::from(
                "QMP descriptor request used foreign ancillary data",
            ));
        }
        let expected = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as usize;
        if (*header).cmsg_len as usize != expected {
            return Err(format!(
                "QMP descriptor request cmsg length {} != {expected}",
                (*header).cmsg_len
            ));
        }
        let raw = std::ptr::read(libc::CMSG_DATA(header).cast::<RawFd>());
        OwnedFd::from_raw_fd(raw)
    };
    // SAFETY: querying the next header does not dereference it; the message and
    // ancillary buffer remain live.
    if !unsafe { libc::CMSG_NXTHDR(&message, header) }.is_null() {
        return Err(String::from(
            "QMP descriptor request carried extra ancillary data",
        ));
    }
    Ok((request, descriptor))
}

#[cfg(target_os = "linux")]
const fn empty_control_header() -> libc::cmsghdr {
    libc::cmsghdr {
        cmsg_len: 0,
        cmsg_level: 0,
        cmsg_type: 0,
    }
}

#[cfg(target_os = "linux")]
fn join_server<T>(server: thread::JoinHandle<Result<T, String>>) -> Result<T, Box<dyn Error>> {
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
