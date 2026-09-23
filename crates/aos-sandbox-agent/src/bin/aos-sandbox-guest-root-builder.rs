//! Builds the fixed guest-root template from AOS package-pinned executables.
//!
//! This build-time tool accepts one staging root, seven ordered source/digest
//! pairs, and one package binding. It never handles launch credentials or
//! route-specific OpenSSH trust material.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use aos_sandbox_agent::dormant_root_builder::{
    ConcreteGuestRootBuildPlanV1, GuestExecutableInputV1, build_concrete_guest_root_v1,
};
use aos_sandbox_core::ObjectDigest;

fn main() -> ExitCode {
    match configured_plan()
        .and_then(|plan| build_concrete_guest_root_v1(&plan).map_err(|_| "guest root build failed"))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("aos-sandbox-guest-root-builder: {message}");
            ExitCode::FAILURE
        }
    }
}

fn configured_plan() -> Result<ConcreteGuestRootBuildPlanV1, &'static str> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let staging_root = PathBuf::from(required(&mut arguments)?);
    let agent = executable(&mut arguments)?;
    let helper = executable(&mut arguments)?;
    let gate = executable(&mut arguments)?;
    let init = executable(&mut arguments)?;
    let sshd = executable(&mut arguments)?;
    let sshd_session = executable(&mut arguments)?;
    let systemd_init = executable(&mut arguments)?;
    let credential_binding = digest(required(&mut arguments)?)?;
    if arguments.next().is_some() {
        return Err("guest root build accepts exactly sixteen arguments");
    }

    Ok(ConcreteGuestRootBuildPlanV1 {
        staging_root,
        agent,
        helper,
        gate,
        init,
        sshd,
        sshd_session,
        systemd_init,
        credential_binding,
    })
}

fn executable(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<GuestExecutableInputV1, &'static str> {
    Ok(GuestExecutableInputV1 {
        source: PathBuf::from(required(arguments)?),
        digest: digest(required(arguments)?)?,
    })
}

fn required(arguments: &mut impl Iterator<Item = OsString>) -> Result<OsString, &'static str> {
    arguments
        .next()
        .ok_or("guest root build argument is missing")
}

fn digest(value: OsString) -> Result<ObjectDigest, &'static str> {
    let text = value.into_string().map_err(|_| "digest is not ASCII")?;
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err("digest is not 64 hexadecimal digits");
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or("digest is not lowercase hexadecimal")?;
        let low = hex_nibble(pair[1]).ok_or("digest is not lowercase hexadecimal")?;
        decoded[index] = high << 4 | low;
    }
    Ok(ObjectDigest::from_bytes(decoded))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
