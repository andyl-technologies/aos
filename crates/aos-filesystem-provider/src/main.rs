//! Process entry point for the package-owned AOS filesystem provider.

use std::io::{self, Read, Write};

use anyhow::{Context as _, Result, bail};
use aos_ability_model::ABILITY_LIMITS_V1;
use aos_filesystem_provider::handler::native::NativeFilesystem;
const MAX_HANDLER_RESULT_BYTES: usize = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-filesystem-provider: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        bail!("expected one native invocation action");
    }

    let purpose = arguments[0]
        .to_str()
        .context("filesystem handler purpose is not valid UTF-8")?;

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)
        .context("reading bounded invocation")?;
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > ABILITY_LIMITS_V1.max_document_bytes {
        bail!("invocation exceeds the canonical ability document bound");
    }

    let output = NativeFilesystem::production().handle(purpose, &input)?;
    if output.len() > MAX_HANDLER_RESULT_BYTES {
        bail!("response exceeds the command-handler result bound");
    }
    io::stdout()
        .write_all(&output)
        .context("writing command-handler response")?;
    Ok(())
}
