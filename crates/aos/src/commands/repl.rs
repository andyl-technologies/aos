//! `aos repl` — an interactive Nix REPL with the AOS package set loaded.
//!
//! Uses the selected evaluator from [`NixRunner`]. The `nix-cli` evaluator
//! launches `nix repl` on the repository's `default.nix`; native or shadow
//! evaluators run the in-process AOS REPL with the same loaded file context.

use anyhow::Result;

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos repl` — start an interactive Nix REPL with `default.nix` loaded.
///
/// # Errors
///
/// Returns an error if the selected REPL cannot start or exits unsuccessfully.
pub fn run(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let nix_file = nix.root().join("default.nix");

    if nix.evaluator_name() == "nix-cli" {
        printer.info(&format!("Starting Nix REPL with {}", nix_file.display()));
    } else {
        printer.info(&format!(
            "Starting {} REPL with {}",
            nix.evaluator_name(),
            nix_file.display()
        ));
    }

    nix.repl(&nix_file)
}
