//! Validates a captured QEMU x86 I/O map for white-box doorbell setup.

use std::{env, fs, process::ExitCode};

use crucible_qemu::validate_x86_whitebox_hmp_mtree;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let _program = args.next();
    let path = args
        .next()
        .ok_or_else(|| String::from("usage: crucible-qemu-whitebox-map-validate <mtree-file>"))?;
    if args.next().is_some() {
        return Err(String::from(
            "usage: crucible-qemu-whitebox-map-validate <mtree-file>",
        ));
    }
    let output =
        fs::read_to_string(&path).map_err(|error| format!("read `{}`: {error}", path.display()))?;
    let validation = validate_x86_whitebox_hmp_mtree(&output).map_err(|error| error.to_string())?;
    println!("PASS");
    println!("port=0x{:04x}", validation.port());
    println!("region={}", validation.observed_region());
    Ok(())
}
