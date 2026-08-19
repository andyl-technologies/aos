//! Validates the live kernel command line before normal initrd storage setup.

use std::env;
use std::fs;
use std::process::ExitCode;

use aos_boot_identity::parse_normal;

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let path = arguments.next().unwrap_or_else(|| "/proc/cmdline".into());

    if arguments.next().is_some() {
        eprintln!("usage: aos-boot-identity [CMDLINE_PATH]");
        return ExitCode::from(2);
    }

    let cmdline = match fs::read_to_string(&path) {
        Ok(cmdline) => cmdline,
        Err(error) => {
            eprintln!(
                "aos-boot-identity: cannot read {}: {error}",
                path.to_string_lossy()
            );
            return ExitCode::FAILURE;
        }
    };

    match parse_normal(&cmdline) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-boot-identity: rejected normal boot: {error}");
            ExitCode::FAILURE
        }
    }
}
