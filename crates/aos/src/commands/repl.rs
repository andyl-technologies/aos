use anyhow::Result;

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos repl` — start an interactive Nix REPL with `default.nix` loaded.
pub fn run(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let nix_file = nix.root().join("default.nix");

    printer.info(&format!("Starting Nix REPL with {}", nix_file.display()));

    nix.repl(&nix_file)
}
