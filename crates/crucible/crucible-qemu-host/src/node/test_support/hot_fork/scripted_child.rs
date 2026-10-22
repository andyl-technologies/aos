//! Scripted retained-child transport used by node hot-fork fixtures.

use super::*;

pub(super) fn spawn_scripted_child_qmp(
    mut stream: std::os::unix::net::UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    qmp_generation: u64,
    monitor_generation: u64,
) {
    thread::spawn(move || {
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        let _ = stream.write_all(b"{\"QMP\":{\"version\":{},\"capabilities\":[\"oob\"]}}\r\n");
        let reader_stream = match stream.try_clone() {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let mut reader = BufReader::new(reader_stream);
        loop {
            let mut request = String::new();
            match reader.read_line(&mut request) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let command = serde_json::from_str::<serde_json::Value>(&request)
                .ok()
                .and_then(|request| {
                    request
                        .get("execute")
                        .or_else(|| request.get("exec-oob"))?
                        .as_str()
                        .map(str::to_owned)
                });
            let response = match command.as_deref() {
                Some("crucible-hot-fork-child-qmp") => serde_json::json!({
                    "return": {
                        "schema-version": 8,
                        "generation": qmp_generation,
                        "template-generation": template_generation,
                        "monitor-generation": monitor_generation,
                        "staged": true,
                        "fdname": descriptor_name.as_str(),
                        "socket-cookie": socket_cookie,
                        "retained-fd": 33,
                        "resource-plan-bound": true,
                        "nonblocking-unix-stream": true,
                        "monitor-basis-bound": true,
                        "monitor-disposition-bound": true,
                        "monitor-socket-resources-bound": true,
                        "reinitializer-prepared": true,
                        "reinitialized": true,
                        "disposition-complete": true,
                        "readiness-proof-acknowledged": true
                    }
                }),
                Some("query-status") => serde_json::json!({
                    "return": { "status": "running", "singlestep": false, "running": true }
                }),
                _ => serde_json::json!({ "return": {} }),
            };
            if writeln!(stream, "{response}").is_err() {
                return;
            }
            if command.as_deref() == Some("quit") {
                return;
            }
        }
    });
}

pub(super) fn mark_stream_bound(
    stream: &mut Option<RetainedStream>,
    description: &'static str,
) -> Result<(), QemuNodeChannelError> {
    let Some((_name, _cookie, bound)) = stream.as_mut() else {
        return Err(QemuNodeChannelError::new(
            "seal scripted hot-fork child stream",
            format!("scripted {description} stage is absent"),
        ));
    };
    *bound = true;
    Ok(())
}

pub(super) fn write_child_file_payloads(
    child_files: Option<&ScriptedChildFiles>,
) -> Result<(), crate::QemuHotForkCommandError> {
    let Some(plan) = child_files else {
        return Ok(());
    };
    for (index, descriptor) in plan.descriptors.iter().enumerate() {
        let descriptor =
            descriptor
                .try_clone()
                .map_err(|source| crate::QemuHotForkCommandError::Rejected {
                    source: QemuNodeChannelError::new(
                        "clone scripted hot-fork child-file destination",
                        source.to_string(),
                    ),
                })?;
        let file = std::fs::File::from(descriptor);
        let bytes = if index == 0 {
            b"scripted-hot-fork-vmstate-v1\n".as_slice()
        } else {
            b"scripted-hot-fork-root-overlay-v1\n".as_slice()
        };
        std::os::unix::fs::FileExt::write_all_at(&file, bytes, 0).map_err(|source| {
            crate::QemuHotForkCommandError::Rejected {
                source: QemuNodeChannelError::new(
                    "write scripted hot-fork child-file destination",
                    source.to_string(),
                ),
            }
        })?;
    }
    Ok(())
}
