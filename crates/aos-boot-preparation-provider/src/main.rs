//! Process entry point for the boot preparation provider.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, bail};
use aos_boot_preparation_provider::handler::BootPreparationProvider;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-boot-preparation-provider: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 || !matches!(arguments[0].as_str(), "apply" | "remove" | "observe") {
        bail!("usage: aos-boot-preparation-provider <apply|remove|observe>");
    }

    let mut input = Vec::new();
    io::stdin()
        .take((256 * 1024) + 1)
        .read_to_end(&mut input)
        .context("reading bounded invocation")?;
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > (256 * 1024) {
        bail!("invocation exceeds the canonical ability document bound");
    }

    let output = BootPreparationProvider::production().handle(&arguments[0], &input)?;
    if output.len() > 256 * 1024 {
        bail!("response exceeds the command-handler result bound");
    }
    io::stdout()
        .write_all(&output)
        .context("writing command-handler response")
}
