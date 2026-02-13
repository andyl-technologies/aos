use clap::CommandFactory;
use clap_complete::generate;

use crate::cli::Cli;

/// `aos completions <shell>` — generate shell completion scripts.
pub fn run(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut std::io::stdout());
}
