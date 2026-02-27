use anyhow::Result;

use aos::nix::NixRunner;
use aos::output::Printer;

/// `aos shell` — enter the project's development shell.
pub fn run(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let shell_nix = nix.root().join("shell.nix");
    let nix_file = if shell_nix.is_file() {
        shell_nix
    } else {
        nix.root().join("default.nix")
    };

    printer.info(&format!(
        "Entering development shell ({})",
        nix_file.display()
    ));

    nix.shell(&nix_file)
}
