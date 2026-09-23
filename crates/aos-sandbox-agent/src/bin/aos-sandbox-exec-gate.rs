//! Fixed OpenSSH forced command for an already admitted guest execution.
//!
//! The certificate and sshd configuration select this binary with exact
//! identity arguments. The root-owned guest process bridge independently
//! checks the same claim and its private process ledger before returning one
//! PTY master; this binary never runs a caller-provided command or shell.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

use aos_sandbox_agent::openssh_gate::OpenSshGateClaimV1;
#[cfg(target_os = "linux")]
use aos_sandbox_agent::openssh_gate_linux::load_openssh_gate_claim_v1;
#[cfg(target_os = "linux")]
use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};

const BRIDGE_PATH: &str = "/run/aos-sandbox-agent/exec-gate.sock";
const BRIDGE_SUCCESS: &[u8; 8] = b"AOSGOK01";
const STREAM_SUCCESS: &[u8; 8] = b"AOSGOS01";
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let claim = load_openssh_gate_claim_v1()?;
    require_exact_arguments(&claim)?;
    match request_io(&claim)? {
        BridgeIo::Pty(descriptor) => relay_pty(descriptor)?,
        BridgeIo::Stream(descriptors) => relay_stream(descriptors)?,
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("OpenSSH execution gate requires Linux".into())
}

fn require_exact_arguments(claim: &OpenSshGateClaimV1) -> Result<(), Box<dyn std::error::Error>> {
    let expected = [
        "--operation-id".to_owned(),
        hex_id(&claim.binding.attach_operation_id),
        "--execution-id".to_owned(),
        hex_id(&claim.binding.execution_id),
        "--incarnation-id".to_owned(),
        hex_id(&claim.binding.incarnation_id),
        "--assignment-epoch".to_owned(),
        claim.binding.assignment_epoch.to_string(),
        "--principal-id".to_owned(),
        hex_id(&claim.binding.principal_id),
        "--audit-id".to_owned(),
        hex_id(&claim.binding.audit_id),
    ];
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments != expected {
        return Err("OpenSSH execution gate identity does not match protected claim".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
enum BridgeIo {
    Pty(OwnedFd),
    Stream([OwnedFd; 3]),
}

#[cfg(target_os = "linux")]
fn request_io(claim: &OpenSshGateClaimV1) -> Result<BridgeIo, Box<dyn std::error::Error>> {
    let request = claim.encode_bridge_request()?;
    let mut socket = SeqpacketSocket::connect(Path::new(BRIDGE_PATH))?;
    if socket.peer().credentials().uid() != 0 {
        return Err("OpenSSH execution bridge is not root-owned".into());
    }
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    loop {
        match socket.send(&request) {
            Ok(()) => break,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    }
    let descriptor_count = if claim.pty { 1 } else { 3 };
    let success = if claim.pty {
        BRIDGE_SUCCESS
    } else {
        STREAM_SUCCESS
    };
    loop {
        match socket.receive_with_descriptors(8, descriptor_count) {
            Ok(record) => {
                let bound = socket.bind_received_descriptors(record)?;
                if bound.payload() != success
                    || bound.descriptors().len() != descriptor_count
                    || bound.subject().credentials().uid() != 0
                    || bound.subject().credentials().pid() != bound.peer().credentials().pid()
                {
                    return Err("OpenSSH execution bridge refused descriptor handoff".into());
                }
                let (_, _, mut descriptors, _) = bound.into_parts();
                if claim.pty {
                    return descriptors
                        .pop()
                        .map(BridgeIo::Pty)
                        .ok_or_else(|| "OpenSSH execution bridge omitted PTY".into());
                }
                return descriptors
                    .try_into()
                    .map(BridgeIo::Stream)
                    .map_err(|_| "OpenSSH execution bridge omitted stream descriptors".into());
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(target_os = "linux")]
fn relay_stream(descriptors: [OwnedFd; 3]) -> Result<(), Box<dyn std::error::Error>> {
    let [input, output, error] = descriptors;
    let input_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut input_pipe = File::from(input);
        std::io::copy(&mut std::io::stdin().lock(), &mut input_pipe)?;
        Ok(())
    });
    let output_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut output_pipe = File::from(output);
        std::io::copy(&mut output_pipe, &mut std::io::stdout().lock())?;
        Ok(())
    });
    let error_thread = std::thread::spawn(move || -> std::io::Result<()> {
        let mut error_pipe = File::from(error);
        std::io::copy(&mut error_pipe, &mut std::io::stderr().lock())?;
        Ok(())
    });
    output_thread.join().map_err(|_| "stdout relay failed")??;
    error_thread.join().map_err(|_| "stderr relay failed")??;
    drop(input_thread);
    Ok(())
}

fn relay_pty(descriptor: OwnedFd) -> Result<(), Box<dyn std::error::Error>> {
    let mut output_master = File::from(descriptor);
    let mut input_master = output_master.try_clone()?;
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let mut buffer = [0u8; 8192];
        while let Ok(count) = input.read(&mut buffer) {
            if count == 0 || input_master.write_all(&buffer[..count]).is_err() {
                break;
            }
        }
    });

    let mut output = std::io::stdout().lock();
    let mut buffer = [0u8; 8192];
    loop {
        match output_master.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => output.write_all(&buffer[..count])?,
            Err(error) if error.raw_os_error() == Some(5) => break,
            Err(error) => return Err(error.into()),
        }
    }
    output.flush()?;
    Ok(())
}

fn hex_id(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(32);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}
