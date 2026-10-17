//! Independent Native process observation without enabling OCI dispatch.
//!
//! The private configuration contains exact observed argv/environment bytes.
//! Its public projection contains hashes and process lifetime only; later
//! acceptance activation is a separate configuration and current-ELF check.

use std::{
    fs::File,
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use super::{files, observations::Native};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Configuration {
    pub version: u32,
    pub process_id: u32,
    pub start_ticks: aos_hub_core::direct_upload::WireInteger,
    pub argv_base64: String,
    pub environment_base64: String,
}

impl Drop for Configuration {
    fn drop(&mut self) {
        self.argv_base64.zeroize();
        self.environment_base64.zeroize();
    }
}

fn proc_bytes(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= maximum,
        "OCI process observation exceeds bound"
    );
    Ok(bytes)
}

fn lifetime(directory: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    ensure!(
        directory.metadata()?.uid() == rustix::process::geteuid().as_raw(),
        "OCI Native process owner differs"
    );
    let stat = proc_bytes(&directory.join("stat"), 8192)?;
    let stat = std::str::from_utf8(&stat)?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| anyhow::anyhow!("OCI process stat malformed"))?;
    let fields: Vec<_> = fields.split_ascii_whitespace().collect();
    ensure!(
        fields.len() >= 20 && fields[0] != "Z",
        "OCI Native process lifetime unavailable"
    );
    fields[19]
        .parse()
        .map_err(|_| anyhow::anyhow!("OCI process start ticks malformed"))
}

pub(super) fn observe(
    pid: u32,
    executable: &Path,
    configuration_output: &Path,
    observation_output: &Path,
) -> Result<String> {
    ensure!(pid > 0, "OCI Native process id invalid");
    let directory = Path::new("/proc").join(pid.to_string());
    let ticks = lifetime(&directory)?;
    let selected = std::fs::canonicalize(executable)?;
    let actual = std::fs::read_link(directory.join("exe"))?;
    ensure!(actual == selected, "OCI Native process executable differs");
    let (executable_sha256, _) = files::hash_installed(&selected)?;
    let argv = Zeroizing::new(proc_bytes(&directory.join("cmdline"), 32 * 1024)?);
    let environment = Zeroizing::new(proc_bytes(&directory.join("environ"), 32 * 1024)?);
    ensure!(
        !argv.is_empty()
            && argv.last() == Some(&0)
            && (environment.is_empty() || environment.last() == Some(&0)),
        "OCI Native process configuration malformed"
    );
    let configuration = serde_json::to_vec(&Configuration {
        version: 1,
        process_id: pid,
        start_ticks: aos_hub_core::direct_upload::WireInteger::new(ticks),
        argv_base64: STANDARD.encode(&argv),
        environment_base64: STANDARD.encode(&environment),
    })?;
    ensure!(
        configuration.len() <= files::DOCUMENT_LIMIT as usize,
        "OCI Native private configuration exceeds bound"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let report = Native {
        version: 1,
        observation_scope: "oci_sdk_native_process_readback".into(),
        observed_at: now,
        process_id: pid,
        start_ticks: aos_hub_core::direct_upload::WireInteger::new(ticks),
        executable_sha256,
        configuration_sha256: files::digest(&configuration),
    };
    ensure!(
        lifetime(&directory)? == ticks
            && std::fs::read_link(directory.join("exe"))? == selected
            && proc_bytes(&directory.join("cmdline"), 32 * 1024)? == argv.as_slice()
            && proc_bytes(&directory.join("environ"), 32 * 1024)? == environment.as_slice(),
        "OCI Native process changed during observation"
    );
    files::write_new(configuration_output, &configuration)?;
    let bytes = serde_json::to_vec_pretty(&report)?;
    files::write_new(observation_output, &bytes)?;
    Ok(files::digest(&bytes))
}
