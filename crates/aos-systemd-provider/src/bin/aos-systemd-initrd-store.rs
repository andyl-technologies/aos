//! Restores the durable initrd journal's store transport before admission.

use std::path::PathBuf;

use anyhow::{Result, ensure};

#[path = "../executable.rs"]
mod executable;
#[path = "../initrd_store.rs"]
mod initrd_store;
#[path = "../store_closure.rs"]
mod store_closure;

fn run() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    ensure!(
        arguments.len() == 4
            && arguments[0] == "--nix-store"
            && arguments[2] == "--state-directory",
        "initrd store restoration requires the selected Nix tool and journal directory"
    );
    let nix_store = PathBuf::from(&arguments[1]);
    executable::validate_store_executable(&nix_store, "--nix-store")?;
    let journal = PathBuf::from(&arguments[3]);
    ensure!(
        journal.is_absolute(),
        "initrd journal directory is not absolute"
    );
    initrd_store::restore(&nix_store, &journal)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-systemd-initrd-store: {error:#}");
        std::process::exit(1);
    }
}
