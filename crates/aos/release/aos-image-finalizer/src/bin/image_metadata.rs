//! Writes shared canonical image metadata from a bounded build-input record.

use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use anyhow::{Context as _, Result, ensure};
use aos_image_finalizer::metadata::{SelfContainedInput, self_contained};

fn main() -> Result<()> {
    let arguments = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    ensure!(
        arguments.len() == 1,
        "usage: aos-image-metadata OUTPUT < INPUT.json"
    );
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "image metadata input exceeds its bound"
    );
    let input: SelfContainedInput =
        serde_json::from_slice(&bytes).context("decoding image metadata input")?;
    let metadata = self_contained(&input)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&arguments[0])?;
    output.write_all(&metadata)?;
    output.sync_all()?;
    Ok(())
}
