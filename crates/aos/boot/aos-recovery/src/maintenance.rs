//! Authorizes and contains recovery maintenance for encrypted persistent state.
//!
//! The recovery key is obtained from `systemd-ask-password` and connected
//! directly to `cryptsetup` over a pipe; it is never written to a temporary
//! file or copied into a Rust string. The exact keyslot comes from the single
//! supported `systemd-recovery` LUKS token, not a guessed slot number.

use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::process::{Command, Stdio};

const VAR_MAPPER: &str = "/dev/mapper/var";
const VAR_MOUNT: &str = "/var";
const METADATA: &str = "/run/aos-recovery/var-luks.json";
const MAX_LUKS_METADATA_BYTES: u64 = 16 * 1024 * 1024;

use crate::device::discover_host_layout;

const RECOVERY_SLOT_FILTER: &str = r#"
  . as $root
  | [.tokens | to_entries[]
    | select(.value.type == "systemd-recovery")
    | select((.value.keyslots | type) == "array" and (.value.keyslots | length) == 1)
    | select(.value.keyslots[0] | type == "string" and test("^(0|[1-9][0-9]*)$"))
    | select(.value.keyslots[0] as $slot | $root.keyslots[$slot] != null)] as $recovery
  | if ($recovery | length) != 1 then
      error("expected one single-keyslot systemd-recovery token")
    elif ([.tokens | to_entries[]
      | select(.value.type == "systemd-tpm2")
      | .value.keyslots[]?] | index($recovery[0].value.keyslots[0])) != null then
      error("recovery and TPM tokens share a keyslot")
    else $recovery[0].value.keyslots[0]
    end
"#;

/// Reports a failure to authenticate, mount, or contain persistent state.
#[derive(Debug)]
pub enum MaintenanceError {
    /// A fixed-path file or process operation failed.
    Io(io::Error),
    /// LUKS metadata did not identify one supported recovery keyslot.
    RecoveryToken(String),
    /// The supplied recovery key did not unlock its exact keyslot.
    Authentication,
    /// Persistent state could not be mounted with the required flags.
    Mount(String),
    /// An authenticated operation was requested before unlock.
    NotAuthenticated,
    /// The maintenance shell failed to start or exited unsuccessfully.
    Shell(String),
    /// Persistent state could not be fully unmounted and closed.
    Cleanup(String),
}

impl fmt::Display for MaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O failure: {error}"),
            Self::RecoveryToken(reason) => write!(formatter, "recovery token rejected: {reason}"),
            Self::Authentication => formatter.write_str("recovery key authentication failed"),
            Self::Mount(reason) => write!(formatter, "persistent-state mount failed: {reason}"),
            Self::NotAuthenticated => formatter.write_str("persistent state is not authenticated"),
            Self::Shell(reason) => write!(formatter, "maintenance shell failed: {reason}"),
            Self::Cleanup(reason) => write!(formatter, "persistent-state cleanup failed: {reason}"),
        }
    }
}

impl Error for MaintenanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for MaintenanceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Tracks whether this recovery process has authenticated and mounted `/var`.
#[derive(Debug, Default)]
pub struct MaintenanceSession {
    authenticated: bool,
    mounted: bool,
    mapper_open: bool,
}

/// Proves recovery-key authentication for one bounded restore transaction.
#[derive(Debug)]
pub struct RestoreAuthorization {
    _private: (),
}

impl MaintenanceSession {
    /// Creates a session with persistent state closed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports whether persistent state is currently authenticated and mounted.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Reports that the persistent-state mapper is open or requires cleanup.
    #[must_use]
    pub fn mapper_is_open(&self) -> bool {
        self.mapper_open || std::path::Path::new(VAR_MAPPER).exists()
    }

    /// Prompts for the recovery key, opens its exact token keyslot, and mounts `/var`.
    ///
    /// The automatic LUKS token path is bypassed by supplying both the exact
    /// recovery keyslot and a key stream. On every failure the partial mapping
    /// is closed before control returns to the menu.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError`] for malformed recovery-token metadata, a
    /// wrong key, or failure to mount the authenticated filesystem.
    pub fn authenticate(&mut self) -> Result<(), MaintenanceError> {
        if self.authenticated {
            return Ok(());
        }
        if self.mapper_open || std::path::Path::new(VAR_MAPPER).exists() {
            self.mapper_open = true;
            self.close_mapping()?;
        }
        let layout = discover_host_layout()
            .map_err(|error| MaintenanceError::RecoveryToken(error.to_string()))?;
        fs::create_dir_all(VAR_MOUNT)?;
        if let Err(error) = open_with_recovery_key(&layout.var) {
            self.mapper_open = std::path::Path::new(VAR_MAPPER).exists();
            return Err(error);
        }
        self.mapper_open = true;

        let output = Command::new("/bin/mount")
            .args(["-t", "ext4", "-o", "rw,nosuid,nodev", VAR_MAPPER, VAR_MOUNT])
            .output()?;
        if !output.status.success() {
            self.close_mapping()?;
            return Err(MaintenanceError::Mount(stderr_reason(&output)));
        }

        self.authenticated = true;
        self.mounted = true;
        Ok(())
    }

    /// Authenticates one restore transaction without mounting persistent state.
    ///
    /// The mapping is closed before the capability is returned. Possession of
    /// the opaque value authorizes only the caller's immediate bounded restore;
    /// it contains neither key material nor a reusable credential.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError`] when token discovery, password prompting,
    /// exact-keyslot unlock, or mapping cleanup fails.
    pub fn authorize_restore(&mut self) -> Result<RestoreAuthorization, MaintenanceError> {
        if self.authenticated {
            return Err(MaintenanceError::Cleanup(
                "lock the mounted maintenance session before restoring".into(),
            ));
        }
        if self.mapper_open || std::path::Path::new(VAR_MAPPER).exists() {
            self.mapper_open = true;
            self.close_mapping()?;
        }
        let layout = discover_host_layout()
            .map_err(|error| MaintenanceError::RecoveryToken(error.to_string()))?;
        if let Err(error) = open_with_recovery_key(&layout.var) {
            self.mapper_open = std::path::Path::new(VAR_MAPPER).exists();
            return Err(error);
        }
        self.mapper_open = true;
        self.close_mapping()?;
        Ok(RestoreAuthorization { _private: () })
    }

    /// Runs the maintenance shell with a fixed command path and environment.
    ///
    /// Shell exit never blesses a normal image. The method immediately tries
    /// to unmount and close `/var`; a cleanup failure leaves the session marked
    /// authenticated so the operator can retry an explicit lock or power off.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::NotAuthenticated`] before unlock,
    /// [`MaintenanceError::Shell`] for shell failure, or a cleanup error when
    /// persistent state cannot be closed after exit.
    pub fn run_shell(&mut self) -> Result<(), MaintenanceError> {
        if !self.authenticated || !self.mounted {
            return Err(MaintenanceError::NotAuthenticated);
        }
        println!("AOS authenticated maintenance shell");
        println!("/var is mounted from {VAR_MAPPER}; networking remains disabled.");
        println!("Exiting this shell does not bless or commit a normal image.");

        let status = Command::new("/bin/bash")
            .arg("--noprofile")
            .arg("--norc")
            .env_clear()
            .env("HOME", "/root")
            .env("PATH", "/bin")
            .env("SHELL", "/bin/bash")
            .current_dir(VAR_MOUNT)
            .status()?;
        let cleanup = self.lock();
        if !status.success() {
            cleanup?;
            return Err(MaintenanceError::Shell(format!("exit status {status}")));
        }
        cleanup
    }

    /// Unmounts `/var`, closes the mapping, and clears session authentication.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::Cleanup`] if either the unmount or mapping
    /// close fails. Authentication is cleared only after both effects succeed.
    pub fn lock(&mut self) -> Result<(), MaintenanceError> {
        if !self.authenticated && !self.mapper_open && !std::path::Path::new(VAR_MAPPER).exists() {
            return Ok(());
        }
        if self.mounted {
            let unmount = Command::new("/bin/umount").arg(VAR_MOUNT).output()?;
            if !unmount.status.success() {
                return Err(MaintenanceError::Cleanup(stderr_reason(&unmount)));
            }
            self.mounted = false;
        }
        self.mapper_open = self.mapper_open || std::path::Path::new(VAR_MAPPER).exists();
        self.close_mapping()?;
        self.authenticated = false;
        Ok(())
    }

    fn close_mapping(&mut self) -> Result<(), MaintenanceError> {
        if !self.mapper_open && !std::path::Path::new(VAR_MAPPER).exists() {
            return Ok(());
        }
        let close = Command::new("/bin/cryptsetup")
            .args(["close", "var"])
            .output()?;
        if !close.status.success() || std::path::Path::new(VAR_MAPPER).exists() {
            self.mapper_open = true;
            return Err(MaintenanceError::Cleanup(stderr_reason(&close)));
        }
        self.mapper_open = false;
        Ok(())
    }
}

fn open_with_recovery_key(var_device: &std::path::Path) -> Result<(), MaintenanceError> {
    fs::create_dir_all("/run/aos-recovery")?;
    let keyslot = recovery_keyslot(var_device)?;
    let mut ask = Command::new("/bin/systemd-ask-password")
        .args(["--timeout=0", "AOS /var recovery key:"])
        .stdout(Stdio::piped())
        .spawn()?;
    let password = ask
        .stdout
        .take()
        .ok_or_else(|| MaintenanceError::RecoveryToken("password pipe was not created".into()))?;
    let crypt_status = Command::new("/bin/cryptsetup")
        .args(["open", "--type", "luks", "--key-slot", &keyslot])
        .arg(var_device)
        .arg("var")
        .stdin(Stdio::from(password))
        .status()?;
    let ask_status = ask.wait()?;
    if !ask_status.success() || !crypt_status.success() {
        if std::path::Path::new(VAR_MAPPER).exists() {
            let close = Command::new("/bin/cryptsetup")
                .args(["close", "var"])
                .output()?;
            if !close.status.success() || std::path::Path::new(VAR_MAPPER).exists() {
                return Err(MaintenanceError::Cleanup(stderr_reason(&close)));
            }
        }
        return Err(MaintenanceError::Authentication);
    }
    if !std::path::Path::new(VAR_MAPPER).exists() {
        return Err(MaintenanceError::Authentication);
    }
    Ok(())
}

fn recovery_keyslot(var_device: &std::path::Path) -> Result<String, MaintenanceError> {
    let metadata = File::create(METADATA)?;
    let status = Command::new("/bin/cryptsetup")
        .args(["luksDump", "--dump-json-metadata"])
        .arg(var_device)
        .stdout(Stdio::from(metadata))
        .status()?;
    if !status.success() {
        return Err(MaintenanceError::RecoveryToken(
            "cryptsetup could not read LUKS2 metadata".into(),
        ));
    }
    let size = fs::metadata(METADATA)?.len();
    if size == 0 || size > MAX_LUKS_METADATA_BYTES {
        return Err(MaintenanceError::RecoveryToken(format!(
            "LUKS2 metadata exceeds the {MAX_LUKS_METADATA_BYTES}-byte bound"
        )));
    }

    let output = Command::new("/bin/jq")
        .args(["-er", RECOVERY_SLOT_FILTER, METADATA])
        .output()?;
    if !output.status.success() {
        return Err(MaintenanceError::RecoveryToken(stderr_reason(&output)));
    }
    let keyslot = String::from_utf8(output.stdout)
        .map_err(|error| MaintenanceError::RecoveryToken(error.to_string()))?;
    let keyslot = keyslot.trim_end();
    if keyslot.is_empty() || !keyslot.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MaintenanceError::RecoveryToken(
            "jq returned a malformed recovery keyslot".into(),
        ));
    }
    Ok(keyslot.to_owned())
}

fn stderr_reason(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        format!("exit status {}", output.status)
    } else {
        stderr
    }
}
