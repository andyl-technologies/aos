//! Runs the native configuration overlay handler with checked lower results.

use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_configuration_lower::{lower::Tools, model::Lower, mount};
use serde_json::json;

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-configuration-mount: {error:#}");
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
    io::stdin().take(256 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 256 * 1024,
        "invocation exceeds the package bound"
    );
    let invocation: Invocation = serde_json::from_slice(&bytes)?;
    let input: Lower = serde_json::from_value(invocation.input)?;
    let tools = Tools {
        mkfs: PathBuf::from(env!("AOS_MKFS_EROFS")),
        fsck: PathBuf::from(env!("AOS_FSCK_EROFS")),
    };
    let output = match operation.as_str() {
        "apply" => {
            mount::apply(&input, Path::new(env!("AOS_MOUNT")), &tools)?;
            json!({"path":"/etc"})
        }
        "remove" => {
            mount::remove(&input, Path::new(env!("AOS_UMOUNT")))?;
            json!({})
        }
        "observe" if matches!(invocation.action, Action::Remove) => {
            if mount::current(&input)? {
                json!({"status":"retry-safe"})
            } else {
                json!({"status":"absent"})
            }
        }
        "observe" if mount::current(&input)? => {
            json!({"status":"current", "outputs":{"path":"/etc"}})
        }
        "observe" => json!({"status":"retry-safe"}),
        _ => bail!("expected apply, remove, or observe"),
    };
    io::stdout().write_all(&serde_json::to_vec(&output)?)?;
    Ok(())
}
