//! Command-line entry point for the optional `crucible-guest` emitter.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::ffi::OsString;
use std::process::ExitCode;

use crucible_guest::guest_introspection_agent::{
    GuestIntrospectionAgentConfig, run_guest_introspection_agent,
};
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

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os()
        .skip(1)
        .map(utf8_arg)
        .collect::<Result<Vec<_>, _>>()?;
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage());
        return Ok(());
    }

    if args.first().is_some_and(|arg| arg == "agent") {
        args.remove(0);
        let config = parse_agent_config(&args)?;
        let mut transport = InstructionDoorbellTransport::native()?;
        return run_guest_introspection_agent(config, &mut transport)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error>);
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

fn parse_agent_config(args: &[String]) -> Result<GuestIntrospectionAgentConfig, GuestEmitterError> {
    let mut max_channels =
        crucible_guest::guest_introspection_agent::GUEST_INTROSPECTION_DEFAULT_MAX_CHANNELS;
    let mut ssh_argv: Option<Vec<String>> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--max-channels" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| usage_error("agent --max-channels requires an integer"))?;
                max_channels = value.parse::<u16>().map_err(|_error| {
                    usage_error("agent --max-channels must be an integer in 1..=64")
                })?;
                index += 2;
            }
            "--ssh-program" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| usage_error("agent --ssh-program requires a guest path"))?;
                ssh_argv = Some(vec![value.clone()]);
                index += 2;
            }
            "--ssh-arg" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| usage_error("agent --ssh-arg requires a value"))?;
                ssh_argv
                    .as_mut()
                    .ok_or_else(|| usage_error("agent --ssh-arg requires --ssh-program first"))?
                    .push(value.clone());
                index += 2;
            }
            option => return Err(usage_error(format!("unknown agent option `{option}`"))),
        }
    }
    GuestIntrospectionAgentConfig::new(max_channels, ssh_argv).map_err(usage_error)
}

fn usage_error(message: impl ToString) -> GuestEmitterError {
    GuestEmitterError::Usage {
        message: format!("{}\n\n{}", message.to_string(), usage()),
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
