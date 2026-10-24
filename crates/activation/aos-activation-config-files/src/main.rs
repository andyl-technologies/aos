//! Runs the portable native configuration handler with bounded JSON input.

use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail, ensure};

fn main() {
    if let Err(error) = run() {
        eprintln!("native configuration handler: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let mut state_directory = PathBuf::from("/var/lib/aos/native-service-effects");
    let mut action = None;
    while let Some(argument) = arguments.next() {
        if argument == "--help" || argument == "-h" {
            println!(
                "usage: aos-configuration-provider [--state-directory PATH] {{apply,remove,observe}}"
            );
            return Ok(());
        } else if let Some(path) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--state-directory="))
        {
            state_directory = path.into();
        } else if argument == "--state-directory" {
            state_directory = arguments
                .next()
                .context("--state-directory requires a path")?
                .into();
        } else {
            ensure!(action.is_none(), "expected one native invocation action");
            action = Some(
                argument
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("action is not UTF-8"))?,
            );
        }
    }
    let action = action.context("expected one native invocation action")?;
    let mut document = Vec::new();
    io::stdin()
        .take(256 * 1024 + 1)
        .read_to_end(&mut document)?;
    if document.len() > 256 * 1024 {
        bail!("native invocation exceeds limit");
    }
    let result = aos_activation_config_files::handle(&action, &document, &state_directory)?;
    serde_json::to_writer(io::stdout(), &result)?;
    io::stdout().write_all(b"\n")?;
    Ok(())
}
