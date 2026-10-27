//! SPDX-License-Identifier: Apache-2.0
//! Executes real Apache gateway and engine operations for separate GPL tests.
//!
//! A private Unix socket carries the permissive, versioned test-oracle frames.
//! Gateway mode owns the actual [`DebugGatewayProcess`] and reaps it on shutdown
//! or EOF. Engine mode owns deterministic streams, event logs, and simulation
//! doubles; both modes return owned values through the public process protocol.

use std::env;
use std::error::Error;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

#[path = "qemu_test_oracle/engine.rs"]
mod engine;

use crucible_control_server::DebugGatewayProcess;
use crucible_qemu_protocol::test_oracle::{Frame, FrameKind, Operation, read_frame, write_frame};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-test-oracle: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let engine_mode = args.len() == 1 && args[0] == "--engine";
    if !engine_mode && !(args.len() == 1 || args.len() == 2 && args[1] == "--owner-unix") {
        return Err(invalid("expected --engine or <gateway-executable> [--owner-unix]").into());
    }

    // The test passes one end of a private socket pair as stdin. Inheriting
    // that connection avoids filesystem rendezvous and startup polling.
    let mut stream = UnixStream::from(io::stdin().as_fd().try_clone_to_owned()?);
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    if engine_mode {
        return serve_engine(&mut stream);
    }
    let executable = Path::new(&args[0]);
    if !executable.is_absolute() {
        return Err(invalid("gateway executable must be absolute").into());
    }
    let launched = if args.len() == 2 {
        DebugGatewayProcess::launch_with_owner_unix(executable)
    } else {
        DebugGatewayProcess::launch(executable)
    };
    let gateway = match launched {
        Ok(gateway) => gateway,
        Err(error) => {
            write_frame(
                &mut stream,
                &Frame {
                    kind: FrameKind::Failure,
                    operation: Operation::Ready,
                    request_id: 0,
                    payload: error.to_string().into_bytes(),
                },
            )?;
            return Err(error.into());
        }
    };
    let mut announcement = gateway.control_socket().as_os_str().as_bytes().to_vec();
    announcement.push(0);
    if let Some(endpoint) = gateway.operator_endpoint() {
        announcement.extend_from_slice(endpoint.as_bytes());
    }
    write_frame(
        &mut stream,
        &Frame {
            kind: FrameKind::Success,
            operation: Operation::Ready,
            request_id: 0,
            payload: announcement,
        },
    )?;

    let mut gateway = Some(gateway);
    let mut next_request = 1;
    while let Some(request) = read_frame(&mut stream)? {
        if request.kind != FrameKind::Request || request.request_id != next_request {
            return Err(invalid("oracle requires sequential request frames").into());
        }
        next_request = next_request
            .checked_add(1)
            .ok_or_else(|| invalid("oracle request IDs exhausted"))?;
        let (kind, payload, finished) = match dispatch(&mut gateway, &request) {
            Ok((payload, finished)) => (FrameKind::Success, payload, finished),
            Err(error) => (FrameKind::Failure, error.to_string().into_bytes(), false),
        };
        write_frame(
            &mut stream,
            &Frame {
                kind,
                operation: request.operation,
                request_id: request.request_id,
                payload,
            },
        )?;
        if finished {
            break;
        }
    }
    // EOF also drops the real client, which terminates and reaps its gateway.
    Ok(())
}

fn dispatch(
    gateway: &mut Option<DebugGatewayProcess>,
    request: &Frame,
) -> Result<(Vec<u8>, bool), Box<dyn Error>> {
    if request.operation != Operation::PromoteBackend && !request.payload.is_empty() {
        return Err(invalid("oracle operation requires an empty payload").into());
    }
    match request.operation {
        Operation::Ready => Err(invalid("Ready is an oracle response").into()),
        Operation::Engine => Err(invalid("engine operation requires engine mode").into()),
        Operation::BackendStatus => {
            let status = gateway_mut(gateway)?.client_mut().backend_status()?;
            Ok((status.encode()?, false))
        }
        Operation::Reconnect => {
            gateway_mut(gateway)?.reconnect_control()?;
            Ok((Vec::new(), false))
        }
        Operation::PromoteBackend => {
            let path = Path::new(std::ffi::OsStr::from_bytes(&request.payload));
            if !path.is_absolute() || request.payload.contains(&0) {
                return Err(invalid("backend path must be absolute and contain no NUL").into());
            }
            let generation = gateway_mut(gateway)?.promote_backend(path)?;
            Ok((generation.to_be_bytes().to_vec(), false))
        }
        Operation::Shutdown => {
            let gateway = gateway
                .take()
                .ok_or_else(|| invalid("gateway already shut down"))?;
            let status = gateway.shutdown()?;
            Ok((status.into_raw().to_be_bytes().to_vec(), true))
        }
    }
}

fn gateway_mut(gateway: &mut Option<DebugGatewayProcess>) -> io::Result<&mut DebugGatewayProcess> {
    gateway
        .as_mut()
        .ok_or_else(|| invalid("gateway already shut down"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn serve_engine(stream: &mut UnixStream) -> Result<(), Box<dyn Error>> {
    write_frame(
        stream,
        &Frame {
            kind: FrameKind::Success,
            operation: Operation::Ready,
            request_id: 0,
            payload: b"engine-v2".to_vec(),
        },
    )?;
    let mut engine = engine::EngineOracle::default();
    let mut next_request = 1_u64;
    while let Some(request) = read_frame(stream)? {
        if request.kind != FrameKind::Request || request.request_id != next_request {
            return Err(invalid("oracle requires sequential request frames").into());
        }
        next_request = next_request
            .checked_add(1)
            .ok_or_else(|| invalid("oracle request IDs exhausted"))?;
        let result = if request.operation == Operation::Engine {
            engine.dispatch(&request.payload)
        } else {
            Err(invalid("gateway operation requires gateway mode").into())
        };
        let (kind, payload) = match result {
            Ok(payload) => (FrameKind::Success, payload),
            Err(error) => (FrameKind::Failure, error.to_string().into_bytes()),
        };
        write_frame(
            stream,
            &Frame {
                kind,
                operation: request.operation,
                request_id: request.request_id,
                payload,
            },
        )?;
    }
    Ok(())
}
