//! Emits portable seed DATA from finalized target bytes on the build platform.
//!
//! This entry executes no target image and owns no signer or runtime authority.
//! The input must be readonly and complete; the separate empty output receives
//! canonical objects and a last-published fixed Tree descriptor.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match configured_paths() {
        Ok((input, output)) => match aos_sandbox_storage::run_nix_seed_tree_artifact(&input, &output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("aos-sandbox-nix-seed-tree: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("aos-sandbox-nix-seed-tree: {error}");
            ExitCode::FAILURE
        }
    }
}

fn configured_paths() -> Result<(PathBuf, PathBuf), &'static str> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let input = arguments.next().ok_or("finalized readonly seed root is absent")?;
    let output = arguments.next().ok_or("fresh artifact output directory is absent")?;
    if arguments.next().is_some() {
        return Err("expected exactly a finalized seed root and fresh output directory");
    }
    Ok((input.into(), output.into()))
}
