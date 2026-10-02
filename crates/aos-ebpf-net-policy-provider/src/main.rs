//! Process entry point for the package-owned BPF network policy provider.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, bail};

use aos_ebpf_net_policy_provider::EbpfNetPolicyProvider;
const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_HANDLER_RESULT_BYTES: usize = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-ebpf-net-policy-provider: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 || !matches!(arguments[0].as_str(), "apply" | "remove" | "observe") {
        bail!("usage: aos-ebpf-net-policy-provider <apply|remove|observe>");
    }

    let mut input = Vec::new();
    io::stdin()
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut input)
        .context("reading bounded invocation")?;
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > MAX_DOCUMENT_BYTES {
        bail!("invocation exceeds the canonical ability document bound");
    }

    let output = EbpfNetPolicyProvider::production().handle(&arguments[0], &input)?;
    if output.len() > MAX_HANDLER_RESULT_BYTES {
        bail!("response exceeds the command-handler result bound");
    }
    io::stdout()
        .write_all(&output)
        .context("writing command-handler response")
}
