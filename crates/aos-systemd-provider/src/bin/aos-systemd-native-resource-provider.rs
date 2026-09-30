//! Executes bounded native ancillary resource invocations using systemd ownership receipts.

#[path = "../resource_effects/mod.rs"]
mod resource_effects;

use std::io::{Read, Write};

use anyhow::{Context, Result, bail};
use aos_ability_runtime::activation::Invocation;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("native systemd resource: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let mut credentials = None;
    let mut login_shell = None;
    let mut nologin_shell = None;
    let action = loop {
        let argument = arguments.next().context("missing action")?;
        let target = match argument.as_str() {
            "--systemd-creds" => &mut credentials,
            "--login-shell" => &mut login_shell,
            "--nologin-shell" => &mut nologin_shell,
            _ => break argument,
        };
        if target.is_some() {
            bail!("duplicate pinned executable option");
        }
        *target = Some(arguments.next().context("missing pinned executable")?);
    };
    if arguments.next().is_some() || !matches!(action.as_str(), "apply" | "remove" | "observe") {
        bail!("expected apply, remove, or observe");
    }

    let mut bytes = Vec::new();
    std::io::stdin().take(262_145).read_to_end(&mut bytes)?;
    if bytes.len() > 262_144 {
        bail!("invocation exceeds 256 KiB");
    }
    let limits = aos_contract::limits::JsonLimits {
        max_bytes: 262_144,
        max_depth: 64,
        max_items: 16_384,
        max_string_bytes: 65_536,
    };
    let invocation: Invocation = limits.decode(&bytes, "native resource invocation")?;
    let shells = match (login_shell.as_deref(), nologin_shell.as_deref()) {
        (Some(login), Some(nologin)) => Some((login, nologin)),
        (None, None) => None,
        _ => bail!("both pinned shell executables are required"),
    };
    let output =
        resource_effects::execute(&invocation, &action, credentials.as_deref(), shells).await?;
    serde_json::to_writer(std::io::stdout().lock(), &output)?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}
