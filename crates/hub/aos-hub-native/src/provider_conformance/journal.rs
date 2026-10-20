//! Durable originals and append-only provider observations in an owned journal.
//!
//! ```text
//! original.json
//! 000.intent.json
//! 000.observation.json
//! 001.intent.json          # absence of its observation remains unknown
//! ```

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{ensure, Result};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::model::{Intent, Observation, Original, ResponseCommitment};

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn executable_digest() -> Result<String> {
    let executable = std::env::current_exe()
        .map_err(|_| anyhow::anyhow!("operator executable identity unavailable"))?;
    let mut file = File::open(executable)
        .map_err(|_| anyhow::anyhow!("operator executable cannot be read"))?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 4 * 1024 * 1024 * 1024,
        "operator executable exceeds its identity bound"
    );
    let mut buffer = [0u8; 64 * 1024];
    let mut hash = Sha256::new();
    let mut count = 0u64;
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|_| anyhow::anyhow!("operator executable hash read failed"))?;
        if length == 0 {
            break;
        }
        count += length as u64;
        ensure!(
            count <= 4 * 1024 * 1024 * 1024,
            "operator executable exceeds its identity bound"
        );
        hash.update(&buffer[..length]);
    }
    Ok(hex::encode(hash.finalize()))
}

pub(super) fn read(path: &Path, limit: u64, private: bool) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("operator input cannot be opened"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("operator input metadata unavailable"))?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "operator input is not a bounded regular file"
    );
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o077 == 0,
            "operator input must be owned and inaccessible to other users"
        );
    }
    #[cfg(not(unix))]
    ensure!(
        !private,
        "protected operator custody requires Unix ownership checks"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("operator input cannot be read"))?;
    ensure!(
        bytes.len() as u64 <= limit,
        "operator input exceeds its bound"
    );
    Ok(bytes)
}

pub(super) fn write_new(path: &Path, value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= 256 * 1024,
        "operator journal document exceeds its bound"
    );
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| anyhow::anyhow!("operator output cannot be created"))?;
    temporary
        .write_all(&bytes)
        .map_err(|_| anyhow::anyhow!("operator output cannot be written"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| anyhow::anyhow!("operator output cannot be synchronized"))?;
    temporary
        .persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("operator output exists or cannot be installed"))?;
    File::open(parent)?.sync_all()?;
    Ok(digest(&bytes))
}

pub(super) struct Journal {
    directory: PathBuf,
    pub observations: Vec<Observation>,
}

impl Journal {
    pub fn create(directory: &Path, original: &Original) -> Result<Self> {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(directory)
            .map_err(|_| anyhow::anyhow!("a new owned journal directory is required"))?;
        let parent = directory
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        write_new(&directory.join("original.json"), original)?;
        Ok(Self {
            directory: directory.into(),
            observations: Vec::new(),
        })
    }

    pub fn begin(&self, intent: &Intent) -> Result<usize> {
        let index = self.observations.len();
        ensure!(
            index < 96,
            "operator experiment exceeded its operation bound"
        );
        write_new(
            &self.directory.join(format!("{index:03}.intent.json")),
            intent,
        )?;
        Ok(index)
    }

    pub fn finish(&mut self, index: usize, observation: Observation) -> Result<()> {
        ensure!(
            index == self.observations.len(),
            "operator effect order changed"
        );
        write_new(
            &self.directory.join(format!("{index:03}.observation.json")),
            &observation,
        )?;
        self.observations.push(observation);
        Ok(())
    }

    pub fn received(&self, index: usize, response: &ResponseCommitment) -> Result<()> {
        write_new(
            &self.directory.join(format!("{index:03}.response.json")),
            response,
        )?;
        Ok(())
    }
}

pub(super) fn status(directory: &Path) -> Result<String> {
    let original: Original =
        serde_json::from_slice(&read(&directory.join("original.json"), 64 * 1024, true)?)
            .map_err(|_| anyhow::anyhow!("operator original is invalid"))?;
    let mut observations = Vec::new();
    let mut responses = Vec::new();
    let mut unknown = Vec::new();
    for index in 0..96 {
        let path = directory.join(format!("{index:03}.intent.json"));
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => anyhow::bail!("operator journal metadata unavailable"),
            Ok(_) => {}
        }
        let intent: Intent = serde_json::from_slice(&read(&path, 64 * 1024, true)?)
            .map_err(|_| anyhow::anyhow!("operator intent is invalid"))?;
        let received = directory.join(format!("{index:03}.response.json"));
        match std::fs::symlink_metadata(&received) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => anyhow::bail!("operator response metadata unavailable"),
            Ok(_) => {
                let response: ResponseCommitment =
                    serde_json::from_slice(&read(&received, 64 * 1024, true)?)
                        .map_err(|_| anyhow::anyhow!("operator response commitment is invalid"))?;
                ensure!(
                    response.operation_id == intent.operation_id && response.phase == intent.phase,
                    "operator response differs from its retained original"
                );
                responses.push(response);
            }
        }
        let outcome = directory.join(format!("{index:03}.observation.json"));
        match std::fs::symlink_metadata(&outcome) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                unknown.push(intent.operation_id)
            }
            Err(_) => anyhow::bail!("operator journal metadata unavailable"),
            Ok(_) => {
                let observed: Observation =
                    serde_json::from_slice(&read(&outcome, 64 * 1024, true)?)
                        .map_err(|_| anyhow::anyhow!("operator observation is invalid"))?;
                ensure!(
                    observed.operation_id == intent.operation_id && observed.phase == intent.phase,
                    "operator observation differs from its retained original"
                );
                observations.push(observed);
            }
        }
    }
    Ok(serde_json::to_string(&serde_json::json!({
        "original": original,
        "observations": observations,
        "responses": responses,
        "unknown_operation_ids": unknown,
        "provider_requests_dispatched": 0
    }))?)
}
