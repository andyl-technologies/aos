//! Platform-owned executable capabilities used by host-resource adapters.
//!
//! The selected native handler is already bound to the running packageRuntime
//! artifact. These aliases live in that same immutable output, so a provider
//! package cannot substitute the root-executed nftables binary or the
//! environment and privilege-drop trampoline.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::Command;

use aos_ability_model::ArtifactReference;
use serde::{Deserialize, Serialize};

use super::invalid;

const ENV_ENTRY: &str = "libexec/aos-env";
const NFT_ENTRY: &str = "libexec/aos-nft";
const SETPRIV_ENTRY: &str = "libexec/aos-setpriv";
const SOCAT_ENTRY: &str = "libexec/aos-socat";

/// Retains exact platform-owned helper paths recovered with each request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativePlatformTools {
    env: String,
    nft: String,
    setpriv: String,
    socat: String,
}

impl NativePlatformTools {
    /// Resolves all trusted aliases from the authenticated packageRuntime output.
    pub(super) fn authenticate(artifact: &ArtifactReference) -> Result<Self, io::Error> {
        let root = Path::new(&artifact.store_path);
        if !root.is_absolute()
            || !artifact.store_path.starts_with("/nix/store/")
            || artifact.store_path.contains("/../")
        {
            return Err(invalid("packageRuntime artifact path is not canonical"));
        }
        Ok(Self {
            env: executable_alias(root, ENV_ENTRY)?,
            nft: executable_alias(root, NFT_ENTRY)?,
            setpriv: executable_alias(root, SETPRIV_ENTRY)?,
            socat: executable_alias(root, SOCAT_ENTRY)?,
        })
    }

    /// Builds an empty-environment invocation of the platform nft binary.
    pub(super) fn nft_command(&self) -> Command {
        let mut command = Command::new(&self.env);
        command.args(["-i", &self.nft]);
        command
    }

    /// Builds an empty-environment invocation that drops all ambient authority.
    pub(super) fn command_as(&self, executable: &Path, uid: u32, gid: u32) -> Command {
        let mut command = Command::new(&self.env);
        command
            .arg("-i")
            .arg(&self.setpriv)
            .arg(format!("--reuid={uid}"))
            .arg(format!("--regid={gid}"))
            .arg("--clear-groups")
            .arg("--no-new-privs")
            .arg("--inh-caps=-all")
            .arg("--ambient-caps=-all")
            .arg("--bounding-set=-all")
            .arg("--")
            .arg(executable);
        command
    }

    /// Builds the permanently unprivileged endpoint-broker invocation.
    pub(super) fn broker_command(&self, uid: u32, gid: u32) -> Command {
        self.command_as(Path::new(&self.socat), uid, gid)
    }

    /// Returns the canonical platform-owned broker executable.
    pub(super) fn broker_executable(&self) -> &str {
        &self.socat
    }
}

fn executable_alias(root: &Path, relative: &str) -> Result<String, io::Error> {
    let alias = root.join(relative);
    let executable = fs::canonicalize(&alias)?;
    let metadata = fs::metadata(&executable)?;
    if !executable.starts_with("/nix/store")
        || !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(invalid(
            "packageRuntime platform alias is not a protected executable",
        ));
    }
    executable
        .into_os_string()
        .into_string()
        .map_err(|_| invalid("packageRuntime platform alias is not UTF-8"))
}
