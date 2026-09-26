//! Protected test requirements and canonical namespace-pin verification.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_network::{
    MAXIMUM_RETAINED_NETWORK_NAMESPACES, NetworkNamespaceCustodyRequirementV1,
    NetworkNamespaceStoreName,
};
use rustix::fs::{Mode, OFlags};

const MAXIMUM_STATE_BYTES: u64 = 256 * 1024;

/// Holds the fixture's exact current-boot replay requirements.
pub(crate) struct CustodyState {
    path: PathBuf,
    entries: BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>,
}

impl CustodyState {
    /// Loads the bounded canonical state file, or an empty initial state.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let mut entries = BTreeMap::new();
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: path.to_owned(),
                    entries,
                });
            }
            Err(error) => return Err(error).context("open custody fixture state"),
        };
        if file.metadata()?.len() > MAXIMUM_STATE_BYTES {
            bail!("custody fixture state exceeds its byte bound");
        }
        let mut text = String::new();
        file.take(MAXIMUM_STATE_BYTES + 1)
            .read_to_string(&mut text)
            .context("read custody fixture state")?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAXIMUM_STATE_BYTES {
            bail!("custody fixture state grew beyond its byte bound");
        }
        for line in text.lines() {
            let (name, identity) = parse_state_line(line)?;
            if entries.insert(name, identity).is_some()
                || entries.len() > MAXIMUM_RETAINED_NETWORK_NAMESPACES
            {
                bail!("custody fixture state contains duplicate or excess entries");
            }
        }
        if !text.is_empty() && !text.ends_with('\n') {
            bail!("custody fixture state lacks its canonical final newline");
        }
        Ok(Self {
            path: path.to_owned(),
            entries,
        })
    }

    /// Constructs the exact ordered public replay requirements.
    pub(crate) fn requirements(&self) -> Result<Vec<NetworkNamespaceCustodyRequirementV1>> {
        self.entries
            .iter()
            .map(|(name, identity)| {
                NetworkNamespaceCustodyRequirementV1::new(name.network_handle(), *identity)
                    .context("construct custody fixture replay requirement")
            })
            .collect()
    }

    /// Verifies every protected row against its canonical live pin.
    pub(crate) fn validate_pins(
        &self,
        pins: &PinRoot<'_>,
        host_identity: NamespaceIdentity,
    ) -> Result<()> {
        for (name, identity) in &self.entries {
            self.validate_pin(pins, name, *identity, host_identity)?;
        }
        Ok(())
    }

    /// Verifies one canonical pin against an expected non-host identity.
    pub(crate) fn validate_pin(
        &self,
        pins: &PinRoot<'_>,
        name: &NetworkNamespaceStoreName,
        expected: NamespaceIdentity,
        host_identity: NamespaceIdentity,
    ) -> Result<()> {
        let observed = pins.identity(name)?;
        if expected == host_identity || observed != expected {
            bail!("canonical pin differs from the expected non-host namespace identity");
        }
        Ok(())
    }

    /// Records one exact confirmed custody row durably for restart replay.
    pub(crate) fn record(
        &mut self,
        name: &NetworkNamespaceStoreName,
        identity: NamespaceIdentity,
    ) -> Result<()> {
        match self.entries.get(name) {
            Some(existing) if *existing != identity => {
                bail!("custody fixture state would rebind a name")
            }
            Some(_) => return Ok(()),
            None => {}
        }
        if self.entries.values().any(|existing| *existing == identity)
            || self.entries.len() >= MAXIMUM_RETAINED_NETWORK_NAMESPACES
        {
            bail!("custody fixture state would duplicate or exceed its identity bound");
        }
        self.entries.insert(name.clone(), identity);
        self.persist()
    }

    /// Removes one confirmed custody row durably.
    pub(crate) fn remove(&mut self, name: &NetworkNamespaceStoreName) -> Result<()> {
        self.entries.remove(name);
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("custody fixture state has no parent")?;
        let temporary = parent.join(format!(
            ".custody-fixture.state.{}",
            rustix::process::getpid().as_raw_nonzero()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options
            .open(&temporary)
            .context("create temporary custody fixture state")?;
        let write_result = (|| -> Result<()> {
            for (name, identity) in &self.entries {
                writeln!(
                    file,
                    "{} {} {}",
                    name.as_str(),
                    identity.device,
                    identity.inode
                )?;
            }
            file.sync_all()?;
            std::fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        write_result.context("persist custody fixture state")
    }
}

/// Names the production canonical runtime pin root.
pub(crate) struct PinRoot<'a> {
    path: &'a Path,
}

impl<'a> PinRoot<'a> {
    /// Constructs a pin-root view without creating any path or mount.
    pub(crate) const fn new(path: &'a Path) -> Self {
        Self { path }
    }

    fn identity(&self, name: &NetworkNamespaceStoreName) -> Result<NamespaceIdentity> {
        let path = self.path.join(name.as_str());
        let descriptor = rustix::fs::open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| format!("open canonical namespace pin {}", path.display()))?;
        let namespace = NamespaceFd::from_owned(descriptor, NamespaceKind::Network)
            .context("canonical pin is not a Network namespace")?;
        Ok(namespace.identity())
    }
}

/// Reads the controller-supplied actual host/PID1 namespace identity.
pub(crate) fn read_identity(path: &Path) -> Result<NamespaceIdentity> {
    let file = File::open(path).context("open trusted host namespace identity")?;
    if file.metadata()?.len() > 128 {
        bail!("trusted host namespace identity exceeds its byte bound");
    }
    let mut text = String::new();
    file.take(129)
        .read_to_string(&mut text)
        .context("read trusted host namespace identity")?;
    if text.len() > 128 {
        bail!("trusted host namespace identity grew beyond its byte bound");
    }
    let mut fields = text.trim_end_matches('\n').split(' ');
    let device = parse_u64(fields.next(), "host namespace device")?;
    let inode = parse_u64(fields.next(), "host namespace inode")?;
    if fields.next().is_some() || device == 0 || inode == 0 || !text.ends_with('\n') {
        bail!("trusted host namespace identity is not canonical");
    }
    Ok(NamespaceIdentity { device, inode })
}

fn parse_state_line(line: &str) -> Result<(NetworkNamespaceStoreName, NamespaceIdentity)> {
    let mut fields = line.split(' ');
    let name =
        NetworkNamespaceStoreName::parse(fields.next().context("custody state name is absent")?)
            .context("custody state name is invalid")?;
    let device = parse_u64(fields.next(), "custody state device")?;
    let inode = parse_u64(fields.next(), "custody state inode")?;
    if fields.next().is_some() || device == 0 || inode == 0 {
        bail!("custody state row is not canonical");
    }
    Ok((name, NamespaceIdentity { device, inode }))
}

fn parse_u64(value: Option<&str>, field: &'static str) -> Result<u64> {
    value
        .with_context(|| format!("{field} is absent"))?
        .parse()
        .with_context(|| format!("{field} is not a decimal u64"))
}
