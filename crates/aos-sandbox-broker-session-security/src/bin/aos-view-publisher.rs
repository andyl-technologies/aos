//! Holds one networkless publisher execution after controller registration.
//!
//! This executable participates only in execution registration. It never sends
//! a publication request, opens a publication root, or claims physical effects.

use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};

const SOCKET: &str = "/run/aos/sandbox-publisher/control.sock";
const GREETING_MAGIC: &[u8; 8] = b"AOSPUBI1";
const GREETING_BYTES: usize = 24;
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

fn run() -> Result<(), &'static str> {
    let mut socket = SeqpacketSocket::connect(Path::new(SOCKET))
        .map_err(|_| "controller publisher socket is unavailable")?;
    let deadline = Instant::now() + REGISTRATION_TIMEOUT;
    loop {
        match socket.receive(GREETING_BYTES) {
            Ok(record) => {
                let payload = record.payload();
                if payload.len() != GREETING_BYTES
                    || &payload[..8] != GREETING_MAGIC
                    || payload[8..] == [0; 16]
                {
                    return Err("controller publisher registration greeting is invalid");
                }
                break;
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                if Instant::now() < deadline =>
            {
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err("controller publisher registration failed"),
        }
    }

    // The exact process and socket remain pinned. There is deliberately no
    // challenge, admission, source, or physical publication command here.
    loop {
        match socket.receive(1) {
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                thread::sleep(POLL_INTERVAL)
            }
            _ => return Err("publisher control channel changed"),
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("aos-view-publisher: {message}");
            ExitCode::FAILURE
        }
    }
}
