//! Command entry point for durable provisioning marker observation.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, bail};
use aos_ability_model::ABILITY_LIMITS_V1;
use aos_block_storage_provider::native_provisioning_marker;
const MAX_HANDLER_RESULT_BYTES: usize = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-storage-provisioning-marker-observer: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        bail!("expected one native invocation action");
    }
    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)
        .context("reading bounded invocation")?;
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > ABILITY_LIMITS_V1.max_document_bytes {
        bail!("invocation exceeds the canonical document bound");
    }
    let output = native_provisioning_marker::handle(&arguments[0], &input)?;
    if output.len() > MAX_HANDLER_RESULT_BYTES {
        bail!("response exceeds the handler result bound");
    }
    io::stdout().write_all(&output).context("writing response")
}
