//! SPDX-License-Identifier: GPL-2.0-only
//! Calls the independently linked engine oracle over an inherited Unix socket.
//!
//! Only the v2 test protocol's owned values cross this boundary. Dropping a
//! client closes its connection and reaps the helper, including on test failure.

use std::env;
use std::io;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crucible_qemu_protocol::test_oracle::{Frame, FrameKind, Operation, read_frame, write_frame};
use serde_json::Value;

pub(crate) struct EngineOracle {
    stream: UnixStream,
    child: Child,
    next_request: u64,
}

impl EngineOracle {
    pub(crate) fn launch() -> io::Result<Self> {
        let helper = env::var_os("CRUCIBLE_QEMU_TEST_ORACLE").ok_or_else(|| {
            invalid("CRUCIBLE_QEMU_TEST_ORACLE must name the built Apache helper")
        })?;
        let (stream, child_stream) = UnixStream::pair()?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let child = Command::new(helper)
            .arg("--engine")
            .stdin(Stdio::from(OwnedFd::from(child_stream)))
            .spawn()?;
        let mut oracle = Self {
            stream,
            child,
            next_request: 1,
        };
        let ready = oracle.response(Operation::Ready, 0)?;
        if ready != b"engine-v2" {
            return Err(invalid("unexpected engine oracle announcement"));
        }
        Ok(oracle)
    }

    pub(crate) fn request(&mut self, payload: Value) -> io::Result<Value> {
        let request_id = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or_else(|| invalid("oracle request IDs exhausted"))?;
        write_frame(
            &mut self.stream,
            &Frame {
                kind: FrameKind::Request,
                operation: Operation::Engine,
                request_id,
                payload: serde_json::to_vec(&payload)?,
            },
        )?;
        let bytes = self.response(Operation::Engine, request_id)?;
        serde_json::from_slice(&bytes).map_err(io::Error::from)
    }

    fn response(&mut self, operation: Operation, request_id: u64) -> io::Result<Vec<u8>> {
        let frame = read_frame(&mut self.stream)?
            .ok_or_else(|| invalid("engine oracle closed before its response"))?;
        if frame.operation != operation || frame.request_id != request_id {
            return Err(invalid("engine oracle response identity mismatch"));
        }
        match frame.kind {
            FrameKind::Success => Ok(frame.payload),
            FrameKind::Failure => {
                let message = String::from_utf8(frame.payload)
                    .map_err(|_| invalid("oracle failure is not UTF-8"))?;
                Err(invalid(message))
            }
            FrameKind::Request => Err(invalid("engine oracle returned a request")),
        }
    }
}

impl Drop for EngineOracle {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
        let _ = self.child.wait();
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[path = "engine_oracle/schedule.rs"]
pub(crate) mod schedule;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejected_requests_preserve_the_initialized_engine_stream() -> io::Result<()> {
        let initialize = json!({"operation": "rng-init", "seed": 23, "stream": "node/oracle"});
        let mut oracle = EngineOracle::launch()?;
        let mut reference = EngineOracle::launch()?;
        assert_eq!(
            oracle.request(initialize.clone())?,
            reference.request(initialize)?
        );

        for request in [
            json!({"operation": "unknown"}),
            json!({"operation": "rng-init", "seed": 9, "stream": "other", "unknown": true}),
            json!({"operation": "rng-next", "advance": 1_000_001}),
            json!({"operation": "rng-next", "advance": -1}),
            json!({"operation": "rng-next"}),
        ] {
            assert!(oracle.request(request).is_err());
        }
        let draw = json!({"operation": "rng-next", "advance": 0});
        assert_eq!(oracle.request(draw.clone())?, reference.request(draw)?);
        Ok(())
    }

    #[test]
    fn uninitialized_and_unbounded_engine_requests_are_rejected() -> io::Result<()> {
        let mut oracle = EngineOracle::launch()?;
        for request in [
            json!({"operation": "rng-next", "advance": 0}),
            json!({"operation": "sim-control", "frame": []}),
            json!({"operation": "sim-schedule"}),
            json!({"operation": "sim-create", "slot": 0, "nodes": 17,
                   "capacity": 64, "steps": []}),
            json!({"operation": "sim-create", "slot": 0, "nodes": 1,
                   "capacity": 4097, "steps": []}),
        ] {
            assert!(oracle.request(request).is_err());
        }
        Ok(())
    }
}
