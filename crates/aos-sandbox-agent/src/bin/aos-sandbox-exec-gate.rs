//! Fixed OpenSSH forced command for an already admitted guest execution.
//!
//! The certificate and sshd configuration select this binary with exact
//! identity arguments. The root-owned guest process bridge independently
//! checks the same claim and its private process ledger before returning one
//! PTY master; this binary never runs a caller-provided command or shell.
//!
//! The same installed executable handles sshd's unprivileged certificate
//! profile callback. That mode never contacts the bridge or transfers I/O.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aos_sandbox_agent::openssh_attach_certificate::validate_openssh_attach_certificate_v1;
use aos_sandbox_agent::openssh_gate::OpenSshGateClaimV1;
#[cfg(target_os = "linux")]
use aos_sandbox_agent::openssh_gate_linux::{
    load_openssh_gate_claim_v1, load_unexpired_openssh_attach_profile_v5,
};
use aos_sandbox_core::public_attach_route::public_attach_force_command_v1;
#[cfg(target_os = "linux")]
use aos_sandbox_linux::seqpacket::{SeqpacketError, SeqpacketSocket};

const BRIDGE_PATH: &str = "/run/aos-sandbox-agent/exec-gate.sock";
const BRIDGE_SUCCESS: &[u8; 8] = b"AOSGOK01";
const STREAM_SUCCESS: &[u8; 8] = b"AOSGOS01";
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--authorized-principals")
    {
        emit_authorized_principal(&arguments);
        return Ok(());
    }

    let claim = load_openssh_gate_claim_v1()?;
    require_exact_arguments(&claim, &arguments)?;
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

fn require_exact_arguments(
    claim: &OpenSshGateClaimV1,
    arguments: &[OsString],
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = &claim.binding;
    let command = public_attach_force_command_v1(
        &binding.attach_operation_id,
        &binding.execution_id,
        &binding.incarnation_id,
        binding.assignment_epoch,
        &binding.principal_id,
        &binding.audit_id,
    );
    let expected: Vec<OsString> = command
        .split_ascii_whitespace()
        .skip(1)
        .map(OsString::from)
        .collect();
    if arguments != expected {
        return Err("OpenSSH execution gate identity does not match protected claim".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn emit_authorized_principal(arguments: &[OsString]) {
    // sshd logs the callback's entire argv on nonzero exit. Expected denials
    // return success with no output, keeping the certificate out of that path.
    let principal = (|| {
        if rustix::process::getuid().as_raw() == 0 || rustix::process::geteuid().as_raw() == 0 {
            return None;
        }
        let (certificate_type, certificate_base64) = certificate_arguments(arguments)?;
        // Profile acceptance grants no process access. The real root monitor
        // and held Guest tree, not callback output or leader liveness, join IO.
        let claim = load_unexpired_openssh_attach_profile_v5().ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        match std::fs::symlink_metadata(
            aos_sandbox_agent::openssh_ticket::OPENSSH_TICKET_CLAIM_PATH_V2,
        ) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                let ticket =
                    aos_sandbox_agent::openssh_gate_linux::load_original_ticket_claim_v2().ok()?;
                aos_sandbox_agent::openssh_ticket::validate_original_ticket_certificate_v2(
                    &claim,
                    &ticket,
                    certificate_type,
                    certificate_base64,
                    now,
                )
                .ok()?;
            }
            Err(_) => return None,
        }
        validate_openssh_attach_certificate_v1(&claim, certificate_type, certificate_base64, now)
            .ok()
            .map(|principal| format!("{principal}\n"))
    })();
    if let Some(principal) = principal {
        let _ = std::io::stdout().lock().write_all(principal.as_bytes());
    }
}

fn certificate_arguments(arguments: &[OsString]) -> Option<(&str, &str)> {
    let [mode, certificate_type, certificate_base64] = arguments else {
        return None;
    };
    if mode != "--authorized-principals" {
        return None;
    }
    Some((certificate_type.to_str()?, certificate_base64.to_str()?))
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

#[cfg(test)]
mod tests {
    use super::certificate_arguments;
    use std::ffi::OsString;

    #[test]
    fn callback_arguments_require_exact_mode_and_arity() {
        let arguments = ["--authorized-principals", "kind", "certificate"].map(OsString::from);
        assert_eq!(
            certificate_arguments(&arguments),
            Some(("kind", "certificate"))
        );
        assert!(certificate_arguments(&arguments[..2]).is_none());
        assert!(
            certificate_arguments(&[arguments.as_slice(), &[OsString::from("extra")]].concat())
                .is_none()
        );
        assert!(
            certificate_arguments(&["--operation-id", "kind", "certificate"].map(OsString::from))
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn callback_arguments_reject_non_utf8_without_printing_input() {
        use std::os::unix::ffi::OsStringExt as _;

        let arguments = [
            OsString::from("--authorized-principals"),
            OsString::from("kind"),
            OsString::from_vec(vec![255]),
        ];
        assert!(certificate_arguments(&arguments).is_none());
    }
}
