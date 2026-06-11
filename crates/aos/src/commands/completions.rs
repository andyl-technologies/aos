//! `aos completions` — generate shell completion scripts.
//!
//! Emits a completion script for the requested shell (bash, zsh, fish,
//! ...) on stdout, derived from the clap command tree. Needs no Nix
//! installation or repository root, so it is dispatched before the
//! `NixRunner` is constructed.

use clap::CommandFactory;
use clap_complete::generate;

use crate::cli::Cli;

/// `aos completions <shell>` — generate shell completion scripts.
///
/// Writes the script to stdout; users typically redirect it into their
/// shell's completion directory or `eval` it in their profile.
pub fn run(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut std::io::stdout());
}
