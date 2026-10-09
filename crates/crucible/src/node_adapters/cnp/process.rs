//! Actual provider process custody reserved before private Hello or realization.

use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, ExitStatus};

use crucible_node_provider::{ProviderError, client::ReferenceController, handshake::Handshake};
use rustix::process::{Pid, Signal, getpgid, kill_process_group};

/// Reserves finite native custody before the provider process is launched.
///
/// A trusted installed supervisor allocates this slot before creating Child or
/// sending private credentials. Transport loss cannot revoke the slot. Its
/// implementation retains both actual handles and immutable original ledgers.
pub trait CnpProcessCustodySlot {
    /// Returns the original host-issued finite reservation identity.
    fn identity(&self) -> crucible_node_contract::U64;

    /// Takes actual native resources independently of every runtime borrower.
    fn retain(&mut self, custody: CnpPeerCustody);
}

/// Retains an actual original process and public journals on uncertain native effects.
///
/// This resource holder is not serializable. Provider wire fields cannot create
/// it or discharge its actual process-group and child-reaping obligations.
pub struct CnpPeerCustody {
    pub(super) child: Child,
    pub(super) directory: PathBuf,
    pub(super) controller: Option<ReferenceController>,
    pub(super) handshake: Option<Handshake>,
    pub(super) companion: Option<u32>,
    pub(super) runtime: Option<super::control::CnpRuntimeCustody>,
    pub(super) preparation_started: bool,
    pub(super) conflict_probes: Option<super::original_conflict::ConflictProbeCustody>,
    pub(super) lifecycle_probes: Option<super::lifecycle_resend::LifecycleProbeCustody>,
    group: Option<Pid>,
    kill_requested: bool,
    reaped: Option<ExitStatus>,
}

impl CnpPeerCustody {
    /// Returns the original actual provider process ID for supervisor diagnostics.
    pub fn provider_pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns the original private operational directory under native custody.
    pub fn private_directory(&self) -> &std::path::Path {
        &self.directory
    }

    /// Requests containment and reports only actual reaping plus an empty private group.
    ///
    /// It sends KILL at most once while the original Child remains unreaped.
    /// Later polls never target a possibly reused numeric process identity.
    /// Kernel census failures preserve owned handles and original metadata.
    ///
    /// # Errors
    /// Retains custody on foreign group identity, native signaling/wait failure,
    /// malformed kernel records or exhausted finite census bounds.
    pub fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        if let Some(runtime) = &self.runtime {
            runtime.validate_retained(self.companion)?;
        }
        if self.reaped.is_none() {
            self.reaped = self.child.try_wait()?;
        }
        if self.reaped.is_some() {
            if let Some(handshake) = &mut self.handshake {
                handshake.contain();
            }
            if let Some(controller) = &mut self.controller {
                controller.fence();
            }
            // Once wait reaps Child its numeric identity may be reused. Never
            // send another signal; an unresolved old group remains supervised.
            return group_empty(self.child.id());
        }
        if !self.kill_requested {
            if let Some(handshake) = &mut self.handshake {
                handshake.contain();
            }
            if let Some(controller) = &mut self.controller {
                controller.fence();
            }
            let group = self.group.ok_or(ProviderError::Correlation(
                "CNP private native group unavailable",
            ))?;
            if getpgid(Some(group)).map_err(std::io::Error::from)? != group {
                return Err(ProviderError::Correlation(
                    "CNP provider escaped original private group",
                ));
            }
            kill_process_group(group, Signal::KILL).map_err(std::io::Error::from)?;
            self.kill_requested = true;
        }
        if self.reaped.is_none() {
            self.reaped = self.child.try_wait()?;
        }
        if self.reaped.is_none() || !group_empty(self.child.id())? {
            return Ok(false);
        }
        Ok(true)
    }
}

/// Owns a pre-reserved process slot through failed Hello and native preparation.
pub struct CnpLaunchGuard {
    pub(super) custody: Option<Box<CnpPeerCustody>>,
    slot: Box<dyn CnpProcessCustodySlot>,
}

/// Preserves the pre-reserved actual process when private launch validation fails.
pub struct CnpLaunchFailure {
    /// Explains the failed native installation without claiming reclamation.
    pub error: ProviderError,
    /// Retains the actual Child, private directory and supervision slot.
    pub guard: CnpLaunchGuard,
}

impl CnpLaunchGuard {
    /// Takes the actual newly launched private process without granting model authority.
    ///
    /// The launcher uses CommandExt::process_group(0). Its caller must allocate
    /// `slot` before spawn. A failed check returns the complete original guard.
    ///
    /// # Errors
    /// Returns retained guarded custody on invalid native PID, foreign process
    /// group, or unavailable native group evidence.
    pub fn new(
        child: Child,
        directory: PathBuf,
        slot: Box<dyn CnpProcessCustodySlot>,
    ) -> Result<Self, CnpLaunchFailure> {
        let group = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
        let guard = Self {
            custody: Some(Box::new(CnpPeerCustody {
                child,
                directory,
                controller: None,
                handshake: None,
                companion: None,
                runtime: None,
                preparation_started: false,
                lifecycle_probes: None,
                conflict_probes: None,
                group,
                kill_requested: false,
                reaped: None,
            })),
            slot,
        };
        let result = match group {
            Some(group) => match getpgid(Some(group)).map_err(std::io::Error::from) {
                Ok(actual) if actual == group => Ok(()),
                Ok(_) => Err(ProviderError::Correlation(
                    "CNP launch lacks private process group",
                )),
                Err(error) => Err(error.into()),
            },
            None => Err(ProviderError::Correlation(
                "invalid actual CNP provider PID",
            )),
        };
        match result {
            Ok(()) => Ok(guard),
            Err(error) => Err(CnpLaunchFailure { error, guard }),
        }
    }

    /// Attaches only the controller authenticated to this exact retained Child.
    ///
    /// # Errors
    /// Refuses another actual process or duplicate controller attachment.
    pub fn attach(
        &mut self,
        controller: ReferenceController,
        handshake: Handshake,
    ) -> Result<(), ProviderError> {
        let custody = self
            .custody
            .as_mut()
            .ok_or(ProviderError::Correlation("CNP launch custody transferred"))?;
        if custody.controller.is_some() || controller.peer_pid() != custody.child.id() {
            return Err(ProviderError::Correlation(
                "CNP control is not original retained Child",
            ));
        }
        // The actual registrar owns the connection epoch. Dropping it fences
        // every derived authority, including a still-retained controller.
        custody.handshake = Some(handshake);
        custody.controller = Some(controller);
        Ok(())
    }

    /// Returns the original provider process under the reserved slot.
    pub fn provider_pid(&self) -> Option<u32> {
        self.custody.as_ref().map(|custody| custody.child.id())
    }

    /// Returns the original host-issued finite native reservation identity.
    pub fn supervision_id(&self) -> crucible_node_contract::U64 {
        self.slot.identity()
    }
}

impl Drop for CnpLaunchGuard {
    fn drop(&mut self) {
        if let Some(custody) = self.custody.take() {
            self.slot.retain(*custody);
        }
    }
}

fn group_empty(group: u32) -> Result<bool, ProviderError> {
    let mut entries = 0usize;
    for entry in fs::read_dir("/proc")? {
        entries += 1;
        if entries > 100_000 {
            return Err(ProviderError::ResourceExhausted("CNP process census"));
        }
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        let file = match File::open(entry.path().join("stat")) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(ProviderError::ResourceExhausted("CNP process stat"));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ProviderError::Frame("CNP kernel stat encoding"))?;
        let close = text
            .rfind(')')
            .ok_or(ProviderError::Frame("CNP kernel stat shape"))?;
        let actual = text[close + 1..]
            .split_ascii_whitespace()
            .nth(2)
            .ok_or(ProviderError::Frame("CNP process group omitted"))?
            .parse::<u32>()
            .map_err(|_| ProviderError::Frame("CNP process group invalid"))?;
        if actual == group {
            return Ok(false);
        }
    }
    Ok(true)
}
