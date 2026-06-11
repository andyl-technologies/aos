//! `aos repl` — an interactive Nix REPL with the AOS package set loaded.
//!
//! Launches `nix repl` on the repository's `default.nix`, so `pkgs`,
//! `checks`, and the system attributes are available for interactive
//! exploration. The REPL process inherits the terminal until it exits.

use anyhow::Result;

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos repl` — start an interactive Nix REPL with `default.nix` loaded.
///
/// # Errors
///
/// Returns an error if the `nix repl` process cannot be spawned or exits
/// unsuccessfully.
pub fn run(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let nix_file = nix.root().join("default.nix");

    printer.info(&format!("Starting Nix REPL with {}", nix_file.display()));

    nix.repl(&nix_file)
}
