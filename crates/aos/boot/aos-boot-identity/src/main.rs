//! Validates the live boot command line and reads required UKI identity sections.
//!
//! Section extraction preserves exact text for comparisons after the caller
//! authenticates the signed UKI; extraction itself does not authorize boot.

use std::env;
use std::fs;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::ExitCode;

use aos_boot_identity::parse_normal;

fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|command| command == "read-uki-section")
    {
        return read_uki_section(&arguments);
    }
    let path = match arguments.as_slice() {
        [] => Path::new("/proc/cmdline"),
        [path] => Path::new(path),
        _ => return usage(),
    };

    let cmdline = match fs::read_to_string(&path) {
        Ok(cmdline) => cmdline,
        Err(error) => {
            eprintln!("aos-boot-identity: cannot read {}: {error}", path.display());
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

fn usage() -> ExitCode {
    eprintln!(
        "usage: aos-boot-identity [CMDLINE_PATH] | read-uki-section --uki PATH --section cmdline|osrel"
    );
    ExitCode::from(2)
}

fn read_uki_section(arguments: &[std::ffi::OsString]) -> ExitCode {
    let [_, uki_flag, path, section_flag, section] = arguments else {
        return usage();
    };
    if uki_flag != "--uki" || section_flag != "--section" {
        return usage();
    }
    let Some(section @ ("cmdline" | "osrel")) = section.to_str() else {
        return usage();
    };

    let result = aos_boot_identity::pe::read_uki_text(Path::new(path), section)
        .and_then(|text| io::stdout().lock().write_all(text.as_bytes()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-boot-identity: cannot read UKI identity: {error}");
            ExitCode::FAILURE
        }
    }
}
