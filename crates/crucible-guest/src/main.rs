//! Command-line entry point for the optional `crucible-guest` emitter.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::ffi::OsString;
use std::process::ExitCode;

use crucible_guest::{
    GuestCommandOutcome, GuestEmitterError, InstructionDoorbellTransport, emit_command,
    parse_cli_args, usage,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-guest: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), GuestEmitterError> {
    let args = std::env::args_os()
        .skip(1)
        .map(utf8_arg)
        .collect::<Result<Vec<_>, _>>()?;
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage());
        return Ok(());
    }

    let command = parse_cli_args(args.iter().map(String::as_str))?;
    let mut transport = InstructionDoorbellTransport::native()?;
    match emit_command(&command, &mut transport)? {
        GuestCommandOutcome::Marker { .. } => Ok(()),
        GuestCommandOutcome::Random { reply, .. } => {
            println!("{}", hex_lower(&reply));
            Ok(())
        }
    }
}

fn utf8_arg(arg: OsString) -> Result<String, GuestEmitterError> {
    arg.into_string().map_err(|_arg| GuestEmitterError::Usage {
        message: String::from("crucible-guest arguments must be valid UTF-8"),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
