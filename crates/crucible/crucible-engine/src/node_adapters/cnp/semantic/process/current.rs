//! Reads the actual original generic capsule, registrar and kernel incarnation.
//!
//! The owning launch guard issues these views from its retained real Child.
//! They never enroll a source, select a role, or authorize common/native work.

use std::{cell::Cell, rc::Rc};

#[path = "current/retained_storage.rs"]
mod retained_storage;
pub(in crate::node_adapters::cnp::semantic) use retained_storage::OriginalFreshQueryReadCall;

#[path = "current/metadata.rs"]
mod metadata;

#[path = "current/fresh_current.rs"]
mod fresh_current;

#[path = "current/native_startup.rs"]
mod native_startup;

use crucible_node_format::U64;
use crucible_node_transport::{ProviderError, client::CnpRegistrarRead};

use super::{CnpSemanticProcessCustody, File, Read, executable_guard::OriginalExecutable, fs};

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
    process: u32,
    owner: Rc<ReadOwner>,
    registration: CnpRegistrarRead,
    kernel: KernelIdentity,
    executable: Rc<OriginalExecutable>,
}

impl CnpSemanticSourceRead {
    /// Compares original owning allocation and original registrar as data.
    pub fn same_original(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.registration.same_original(&other.registration)
    }

    /// Compares the same original capsule allocation without reading live state.
    ///
    /// This comparison remains available after containment or actual reaping,
    /// when live source reads correctly refuse. It invokes no registrar, kernel
    /// or installed callback and supplies neither currentness nor reclamation
    /// authority. The caller separately proves the original process was reaped.
    pub fn same_native_owner(&self, native: &super::CnpSemanticProcessCustody) -> bool {
        Rc::ptr_eq(&self.owner, &native.read_owner)
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
    /// Refuses a copied foreign-process handle before inherited state access,
    /// then foreign threads, busy, uncertain, revoked or transferred ownership,
    /// registrar contention/revocation, or changed process/start/group/UID/ELF.
    pub fn ensure_current(&self) -> Result<(), ProviderError> {
        // A copied handle refuses before inherited owner cells or the SDK
        // registrar gate. Kernel identity remains an independent later check.
        if self.process != std::process::id() {
            return Err(ProviderError::Correlation(
                "generic original source read belongs to another process",
            ));
        }
        self.executable.ensure_origin()?;
        self.owner.ensure_current()?;
        self.registration.ensure_current()?;
        self.executable.ensure_current(&self.kernel)?;
        self.registration.ensure_current()?;
        self.owner.ensure_current()?;
        self.executable.ensure_current(&self.kernel)
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
    /// Refuses a foreign creator process before inherited owner cells, then
    /// absent attachment, changed actual process or registrar, busy/transferred
    /// ownership or an unavailable original kernel incarnation.
    pub fn original_source_read(&self) -> Result<CnpSemanticSourceRead, ProviderError> {
        self.ensure_origin()?;
        self.read_owner.ensure_current()?;
        self.authenticate_process()?;
        let controller = self
            .original_controller_data()?
            .ok_or(ProviderError::Correlation(
                "generic original read controller absent",
            ))?;
        // Exactly one surviving original handshake must own this registrar.
        // Typed negotiation stays typed, including an empty selected roster.
        let registration = match (&self.handshake, &self.extension_handshake) {
            (Some(handshake), None) => controller.original_registrar_read(handshake)?,
            (None, Some(handshake)) => controller.original_registrar_read_extensions(handshake)?,
            (None, None) => {
                return Err(ProviderError::Correlation(
                    "generic original read handshake absent",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(ProviderError::Correlation(
                    "generic original read handshake ambiguous",
                ));
            }
        };
        let handle = CnpSemanticSourceRead {
            process: std::process::id(),
            owner: Rc::clone(&self.read_owner),
            registration,
            kernel: self.kernel_identity.ok_or(ProviderError::Correlation(
                "generic original read kernel identity absent",
            ))?,
            executable: Rc::clone(self.executable_guard.as_ref().ok_or(
                ProviderError::Correlation("generic original executable guard absent"),
            )?),
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

impl ReadOwner {
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_original_host_startup_data(
        &self,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        self.ensure_current()
            .map_err(|_| crate::node_contract::RuntimeError::OwnerUnavailable)
    }
}

impl KernelIdentity {
    pub(super) fn original_host_uid_data(&self) -> u32 {
        self.uid
    }
}

impl CnpSemanticSourceRead {
    pub(in crate::node_adapters::cnp::semantic) fn retained_descriptor_views_precredit_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        if self.process != std::process::id() {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        // ReadOwner and registrar are inert shared data, with no descriptor.
        // The actual executable field owns its retained File independently of
        // these handles. Aliased views are conservatively charged per caller.
        self.executable.retained_descriptor_views_precredit_data()
    }
}

#[path = "current/settled17.rs"]
mod settled17;
