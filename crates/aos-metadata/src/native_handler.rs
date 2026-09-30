//! Bounded native activation process transport shared by metadata handlers.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::activation::{Action, Invocation};

const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) fn read_invocation() -> Result<(String, Invocation)> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        arguments.len() == 1 && matches!(arguments[0].as_str(), "apply" | "remove" | "observe"),
        "expected apply, remove, or observe"
    );
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut input)?;
    ensure!(
        u64::try_from(input.len()).unwrap_or(u64::MAX) <= MAX_DOCUMENT_BYTES,
        "metadata invocation exceeds bound"
    );
    let invocation: Invocation =
        aos_contract::canonical::from_slice(&input, "metadata invocation")?;
    let purpose = &arguments[0];
    ensure!(
        purpose == "observe" || (purpose == "apply") == (invocation.action == Action::Apply),
        "native action differs from argv"
    );
    Ok((purpose.clone(), invocation))
}

pub(crate) fn write_response(value: &serde_json::Value) -> Result<()> {
    let output = aos_contract::canonical::canonical_json(value)?;
    ensure!(
        u64::try_from(output.len()).unwrap_or(u64::MAX) <= MAX_DOCUMENT_BYTES,
        "metadata response exceeds bound"
    );
    io::stdout()
        .write_all(&output)
        .context("writing metadata response")
}
