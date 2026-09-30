//! Runs the native configuration image handler with bounded JSON invocation IO.

use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;

use anyhow::{Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_configuration_lower::{lower, model::Input};
use serde_json::json;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-configuration-lower: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let operation = std::env::args().nth(1).unwrap_or_default();
    ensure!(
        std::env::args().len() == 2,
        "expected apply, remove, or observe"
    );
    let mut bytes = Vec::new();
    io::stdin().take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "invocation exceeds the package bound"
    );
    let invocation: Invocation = serde_json::from_slice(&bytes)?;
    let mut input: Input = serde_json::from_value(invocation.input)?;
    let tools = lower::Tools {
        mkfs: PathBuf::from(env!("AOS_MKFS_EROFS")),
        fsck: PathBuf::from(env!("AOS_FSCK_EROFS")),
    };
    input.load_baseline_inventory()?;
    let desired = input.desired_paths()?;
    input.removed_paths.extend(
        input
            .baseline_paths
            .iter()
            .filter(|path| !desired.contains(*path))
            .cloned(),
    );
    input.removed_paths.sort();
    input.removed_paths.dedup();
    if let Some(previous) = &invocation.previous {
        let previous = serde_json::from_value(previous.outputs.clone())?;
        lower::inherit_removals(&mut input, &previous, &tools)?;
    }
    let output = match operation.as_str() {
        "apply" => serde_json::to_value(lower::prepare(
            &input,
            &invocation.id,
            &invocation.revision,
            &tools,
        )?)?,
        // Retained images are generation evidence. Removing an effect does not
        // invalidate a committed generation or a mounted recovery lower.
        "remove" => json!({}),
        "observe" if matches!(invocation.action, Action::Remove) => json!({"status":"absent"}),
        "observe" => match lower::observe(&input, &invocation.id, &invocation.revision, &tools)? {
            Some(output) => json!({"status":"current", "outputs":output}),
            None => json!({"status":"retry-safe"}),
        },
        _ => bail!("expected apply, remove, or observe"),
    };
    io::stdout().write_all(&serde_json::to_vec(&output)?)?;
    Ok(())
}
