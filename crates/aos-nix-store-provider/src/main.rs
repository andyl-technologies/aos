//! Process entry point for package-owned Nix store resources.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, bail};
use aos_ability_model::ABILITY_LIMITS_V1;
use aos_nix_store_provider::handler::NixStoreProvider;
use aos_provider_protocol::{HANDLER_ABI_ARGUMENT, MAX_HANDLER_RESULT_BYTES};

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-nix-store-provider: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != HANDLER_ABI_ARGUMENT {
        bail!(
            "usage: aos-nix-store-provider {HANDLER_ABI_ARGUMENT} \
             <admit|effect|reconcile|cancel|compensate|reconcile-compensation>"
        );
    }

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)
        .context("reading bounded invocation")?;
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > ABILITY_LIMITS_V1.max_document_bytes {
        bail!("invocation exceeds the canonical ability document bound");
    }

    let output = NixStoreProvider::production().handle(&arguments[1], &input)?;
    if output.len() > MAX_HANDLER_RESULT_BYTES {
        bail!("response exceeds the command-handler result bound");
    }
    io::stdout()
        .write_all(&output)
        .context("writing command-handler response")
}
