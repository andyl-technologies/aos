//! Bounded process entry point for native host firewall reconciliation.
//!
//! The runtime passes one action and a resolved JSON invocation. This process
//! emits the operation's outputs or a native observation on standard output.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, ensure};
use aos_network_ruleset_provider::NetworkRulesetProvider;

const MAX_INVOCATION_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-network-ruleset-provider: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["--version"] {
        println!("aos-network-ruleset-provider {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    ensure!(
        arguments.len() == 1,
        "usage: aos-network-ruleset-provider <apply|remove|observe>"
    );
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_INVOCATION_BYTES + 1)
        .read_to_end(&mut input)
        .context("reading bounded native invocation")?;
    ensure!(
        u64::try_from(input.len())? <= MAX_INVOCATION_BYTES,
        "invocation exceeds bound"
    );

    let purpose = arguments[0].to_str().context("action is not UTF-8")?;
    let output = NetworkRulesetProvider::production().handle(purpose, &input)?;
    ensure!(output.len() <= MAX_RESULT_BYTES, "response exceeds bound");
    io::stdout()
        .write_all(&output)
        .context("writing native handler response")
}
