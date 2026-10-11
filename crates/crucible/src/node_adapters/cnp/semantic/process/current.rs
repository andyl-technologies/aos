//! Reads the actual original generic capsule, registrar and kernel incarnation.
//!
//! The owning launch guard issues these views from its retained real Child.
//! They never enroll a source, select a role, or authorize common/native work.

use std::{cell::Cell, rc::Rc};

use crucible_node_contract::{ContentRef, U64};
use crucible_node_provider::{ProviderError, client::CnpRegistrarRead};

use super::{CnpSemanticProcessCustody, File, Read, fs, measure_executable};

pub(in super::super) struct ReadOwner {
    identity: U64,
    current: Cell<bool>,
    busy: Cell<bool>,
}

impl ReadOwner {
    pub(super) fn new(identity: U64) -> Self {
        Self {
            identity,
            current: Cell::new(true),
            busy: Cell::new(false),
        }
    }

    // Used only while the legacy launch guard holds the sole Rc, before any
    // original read handle or successfully authenticated guard can escape.
    pub(super) fn set_initial_identity(&mut self, identity: U64) {
        self.identity = identity;
    }

    pub(in super::super) fn revoke(&self) {
        self.current.set(false);
    }

    fn ensure_current(&self) -> Result<(), ProviderError> {
        if !self.current.get() || self.busy.get() {
            return Err(ProviderError::Correlation(
                "generic original capsule revoked or busy",
            ));
        }
        Ok(())
    }
}

pub(in super::super) struct ReadCall {
    owner: Rc<ReadOwner>,
    finished: bool,
}

impl ReadCall {
    pub(in super::super) fn begin(owner: Rc<ReadOwner>) -> Result<Self, ProviderError> {
        owner.ensure_current()?;
        owner.busy.set(true);
        Ok(Self {
            owner,
            finished: false,
        })
    }

    pub(in super::super) fn finish(mut self, succeeded: bool) {
        if !succeeded {
            self.owner.revoke();
        }
        self.finished = true;
    }
}

impl Drop for ReadCall {
    fn drop(&mut self) {
        if !self.finished {
            self.owner.revoke();
        }
        self.owner.busy.set(false);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct KernelIdentity {
    pid: u32,
    parent: u32,
    group: u32,
    start: u64,
    uid: u32,
}

impl KernelIdentity {
    pub(super) fn capture(pid: u32) -> Result<Self, ProviderError> {
        let mut body = Vec::new();
        File::open(format!("/proc/{pid}/stat"))?
            .take(32 * 1024 + 1)
            .read_to_end(&mut body)?;
        if body.len() > 32 * 1024 {
            return Err(ProviderError::Correlation(
                "generic original kernel stat exceeded bound",
            ));
        }
        let body = std::str::from_utf8(&body)
            .map_err(|_| ProviderError::Correlation("generic original kernel stat malformed"))?;
        let (prefix, tail) = body.rsplit_once(") ").ok_or(ProviderError::Correlation(
            "generic original kernel stat malformed",
        ))?;
        if !prefix.starts_with(&format!("{pid} (")) {
            return Err(ProviderError::Correlation(
                "generic original kernel PID changed",
            ));
        }
        let mut fields = tail.split_ascii_whitespace();
        let _state = fields.next().ok_or(ProviderError::Correlation(
            "generic original kernel state absent",
        ))?;
        let parent = fields.next().and_then(|value| value.parse().ok()).ok_or(
            ProviderError::Correlation("generic original kernel parent absent"),
        )?;
        let group = fields.next().and_then(|value| value.parse().ok()).ok_or(
            ProviderError::Correlation("generic original kernel group absent"),
        )?;
        let start = fields.nth(16).and_then(|value| value.parse().ok()).ok_or(
            ProviderError::Correlation("generic original kernel start absent"),
        )?;
        let metadata = fs::metadata(format!("/proc/{pid}"))?;
        use std::os::unix::fs::MetadataExt;
        let uid = metadata.uid();
        if parent != std::process::id()
            || group != pid
            || uid != rustix::process::geteuid().as_raw()
        {
            return Err(ProviderError::Correlation(
                "generic original kernel ownership changed",
            ));
        }
        Ok(Self {
            pid,
            parent,
            group,
            start,
            uid,
        })
    }

    pub(super) fn ensure_current(&self) -> Result<(), ProviderError> {
        if Self::capture(self.pid)? != *self {
            return Err(ProviderError::Correlation(
                "generic original kernel incarnation changed",
            ));
        }
        Ok(())
    }
}

/// Reads the surviving original generic process capsule and SDK registrar.
///
/// The actual launch custody constructs this handle; no portable record,
/// public insertion or deserialization can replace that origin. The installed
/// source must still authenticate its complete program, role and native journal.
/// Containment, guard transfer, uncertain calls and unwind revoke the owner.
pub struct CnpSemanticSourceRead {
    owner: Rc<ReadOwner>,
    registration: CnpRegistrarRead,
    kernel: KernelIdentity,
    executable: ContentRef,
}

impl CnpSemanticSourceRead {
    /// Compares original owning allocation and original registrar as data.
    pub fn same_original(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.registration.same_original(&other.registration)
    }

    /// Returns the original pre-spawn supervision reservation identity.
    pub fn supervision_id(&self) -> U64 {
        self.owner.identity
    }

    /// Reads original capsule ownership, actual registrar and kernel incarnation.
    ///
    /// This invokes no node, vendor, schema or installed policy callback.
    /// The same SDK registrar must still check the actual native write; this
    /// read is a current source fact, not execution or behavioral authority.
    ///
    /// # Errors
    /// Refuses busy, uncertain, revoked or transferred ownership, registrar
    /// contention/revocation, or changed original process/start/group/UID/ELF.
    pub fn ensure_current(&self) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        self.registration.ensure_current()?;
        self.kernel.ensure_current()?;
        if measure_executable(std::path::Path::new(&format!(
            "/proc/{}/exe",
            self.kernel.pid
        )))? != self.executable
        {
            return Err(ProviderError::Correlation(
                "generic original executable changed",
            ));
        }
        self.kernel.ensure_current()?;
        self.registration.ensure_current()?;
        self.owner.ensure_current()
    }
}

impl CnpSemanticProcessCustody {
    /// Issues a read-only view of this actual attached original capsule.
    ///
    /// Issuance does not qualify realization. A selected installed source must
    /// first authenticate complete original discovery/realization/native bodies,
    /// then retain one exact handle and refuse independent replacements.
    ///
    /// # Errors
    /// Refuses absent attachment, changed actual process or registrar, busy or
    /// transferred ownership, or an unavailable original kernel incarnation.
    pub fn original_source_read(&self) -> Result<CnpSemanticSourceRead, ProviderError> {
        self.read_owner.ensure_current()?;
        self.authenticate_process()?;
        let controller = self.controller.as_ref().ok_or(ProviderError::Correlation(
            "generic original read controller absent",
        ))?;
        let handshake = self.handshake.as_ref().ok_or(ProviderError::Correlation(
            "generic original read handshake absent",
        ))?;
        let handle = CnpSemanticSourceRead {
            owner: Rc::clone(&self.read_owner),
            registration: controller.original_registrar_read(handshake)?,
            kernel: self.kernel_identity.ok_or(ProviderError::Correlation(
                "generic original read kernel identity absent",
            ))?,
            executable: self.expected_executable.clone(),
        };
        handle.ensure_current()?;
        Ok(handle)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These controls panic only when original ownership or uncertainty is lost.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn consumed_window_ack_preserves_original_owner_for_next_window() {
        let owner = Rc::new(ReadOwner::new(U64::new(1)));

        ReadCall::begin(Rc::clone(&owner)).unwrap().finish(true);
        assert!(owner.ensure_current().is_ok());
        ReadCall::begin(Rc::clone(&owner)).unwrap().finish(true);

        assert!(owner.ensure_current().is_ok());
    }

    #[test]
    fn uncertain_native_request_irreversibly_fences_original_owner() {
        let owner = Rc::new(ReadOwner::new(U64::new(1)));

        ReadCall::begin(Rc::clone(&owner)).unwrap().finish(false);

        assert!(owner.ensure_current().is_err());
        assert!(ReadCall::begin(Rc::clone(&owner)).is_err());
    }

    #[test]
    fn in_flight_request_refuses_read_and_drop_preserves_uncertainty() {
        let owner = Rc::new(ReadOwner::new(U64::new(1)));
        let original = ReadCall::begin(Rc::clone(&owner)).unwrap();

        assert!(owner.ensure_current().is_err());
        assert!(ReadCall::begin(Rc::clone(&owner)).is_err());
        drop(original);

        assert!(owner.ensure_current().is_err());
        assert!(ReadCall::begin(Rc::clone(&owner)).is_err());
    }
}
