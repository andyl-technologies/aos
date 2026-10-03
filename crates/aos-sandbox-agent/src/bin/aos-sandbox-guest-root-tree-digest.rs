//! Measures the complete offline AOS guest root using the runtime digest format.

use std::path::PathBuf;
use std::process::ExitCode;
use std::{fmt::Write as _, io::Write as _};

use aos_sandbox_agent::guest_root_tree::measure_offline_guest_root_template_v1;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("aos-sandbox-guest-root-tree-digest: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let root = PathBuf::from(arguments.next().ok_or("template root is absent")?);
    if arguments.next().is_some() || !root.is_absolute() {
        return Err("exactly one absolute template root is required");
    }
    let digest = measure_offline_guest_root_template_v1(&root)
        .map_err(|_| "offline template tree is invalid")?;
    let mut encoded = String::with_capacity(65);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").map_err(|_| "digest formatting failed")?;
    }
    encoded.push('\n');
    std::io::stdout()
        .write_all(encoded.as_bytes())
        .map_err(|_| "digest output failed")?;
    Ok(())
}
