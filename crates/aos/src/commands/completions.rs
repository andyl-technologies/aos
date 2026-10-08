//! `aos completions` — generate shell completion scripts.
//!
//! Emits a completion script for the requested shell (bash, zsh, fish,
//! ...) and installed command on stdout, derived from its clap command tree.
//! Needs no Nix installation or repository root, so it is dispatched before
//! the `NixRunner` is constructed.

use clap::CommandFactory;
use clap_complete::generate;

use crate::cli::{ApmCli, AprCli, Cli};

/// Selects the installed command whose parser supplies completion metadata.
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum CompletionCommand {
    /// Generate completions for the system and development CLI.
    #[default]
    Aos,
    /// Generate completions for the package consumer CLI.
    Apm,
    /// Generate completions for the package registry author CLI.
    Apr,
}

/// Generates a shell completion script for an installed command's parser.
///
/// Writes the script to stdout; users typically redirect it into their
/// shell's completion directory or `eval` it in their profile.
///
/// # Panics
///
/// Panics if the completion generator cannot write to standard output.
pub fn run(shell: clap_complete::Shell, command: CompletionCommand) {
    let mut cmd = match command {
        CompletionCommand::Aos => Cli::command(),
        CompletionCommand::Apm => ApmCli::command(),
        CompletionCommand::Apr => AprCli::command(),
    };
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut std::io::stdout());
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use crate::cli::{ApmCli, AprCli, Cli};

    #[test]
    fn installed_surfaces_generate_their_own_completion_names() {
        for (name, mut command) in [
            ("aos", Cli::command()),
            ("apm", ApmCli::command()),
            ("apr", AprCli::command()),
        ] {
            let mut script = Vec::new();
            clap_complete::generate(clap_complete::Shell::Bash, &mut command, name, &mut script);
            let script = String::from_utf8(script).expect("UTF-8 Bash script");
            assert!(script.contains(&format!("_{name}()")));
            assert!(script.lines().any(|line| {
                line.trim_start()
                    .starts_with(&format!("complete -F _{name} "))
                    && line.ends_with(&format!(" {name}"))
            }));
            if name != "aos" {
                assert!(!script.contains("complete -F _aos "));
            }
        }
    }
}
