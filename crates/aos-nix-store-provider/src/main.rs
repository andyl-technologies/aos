//! Process entry point for package-owned Nix store resources.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, bail};
const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;
use aos_nix_store_provider::handler::NixStoreProvider;
const MAX_HANDLER_RESULT_BYTES: usize = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-nix-store-provider: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        bail!("expected apply, remove, or observe");
    }

    let purpose = arguments[0]
        .to_str()
        .context("Nix store handler purpose is not valid UTF-8")?;

    let mut input = Vec::new();
    io::stdin()
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut input)
        .context("reading bounded invocation")?;
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > MAX_DOCUMENT_BYTES {
        bail!("invocation exceeds the canonical ability document bound");
    }

    let output = NixStoreProvider::production().handle(purpose, &input)?;
    if output.len() > MAX_HANDLER_RESULT_BYTES {
        bail!("response exceeds the command-handler result bound");
    }
    io::stdout()
        .write_all(&output)
        .context("writing command-handler response")
}
