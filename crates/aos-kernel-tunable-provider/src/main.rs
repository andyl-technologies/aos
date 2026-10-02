//! Process entry point for the package-owned kernel-tunable provider.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, bail};
use aos_kernel_tunable_provider::KernelTunableProvider;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-kernel-tunable-provider: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 || !matches!(arguments[0].as_str(), "apply" | "remove" | "observe") {
        bail!("usage: aos-kernel-tunable-provider <apply|remove|observe>");
    }

    let mut input = Vec::new();
    io::stdin()
        .take(256 * 1024 + 1)
        .read_to_end(&mut input)
        .context("reading bounded invocation")?;
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > 256 * 1024 {
        bail!("invocation exceeds the canonical ability document bound");
    }

    let output = KernelTunableProvider::production().handle(&arguments[0], &input)?;
    if output.len() > 256 * 1024 {
        bail!("response exceeds the command-handler result bound");
    }
    io::stdout()
        .write_all(&output)
        .context("writing command-handler response")
}
