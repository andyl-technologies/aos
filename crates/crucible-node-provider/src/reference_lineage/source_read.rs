//! Couples a read-only registrar to its original owning native capsule.

use super::{LineageSourceGuard, NativeCustody, kernel};
use crate::{ProviderError, handshake::RegistrationRead};
use crucible_node_contract::{ContentRef, U64, Validate};
use std::{cell::Cell, rc::Rc};

pub(super) struct SourceReadOwner {
    identity: U64,
    current: Cell<bool>,
    busy: Cell<bool>,
}

impl SourceReadOwner {
    pub(super) fn new(identity: U64) -> Self {
        Self {
            identity,
            current: Cell::new(true),
            busy: Cell::new(false),
        }
    }

    pub(super) fn revoke(&self) {
        self.current.set(false);
    }

    fn ensure_current(&self) -> Result<(), ProviderError> {
        if !self.current.get() || self.busy.get() {
            return Err(ProviderError::Correlation(
                "original source owner read revoked or busy",
            ));
        }
        Ok(())
    }
}

pub(super) struct SourceReadCall<'a> {
    owner: &'a SourceReadOwner,
    finished: bool,
}

impl<'a> SourceReadCall<'a> {
    pub(super) fn new(owner: &'a SourceReadOwner) -> Self {
        owner.busy.set(true);
        Self {
            owner,
            finished: false,
        }
    }

    pub(super) fn finish(mut self, succeeded: bool) {
        if !succeeded {
            self.owner.revoke();
        }
        self.finished = true;
    }
}

impl Drop for SourceReadCall<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.owner.revoke();
        }
        self.owner.busy.set(false);
    }
}

/// Reads one actual original registrar and its surviving native ownership.
///
/// Only the owning source guard can issue this handle. It retains neither
/// commands nor private launch/Hello data and cannot be deserialized. Transfer,
/// reclamation, uncertain control and control unwind revoke it. A successful
/// publication-consumption ACK preserves the same original owning capsule.
/// It supplies a current source fact, never class or execution permission.
pub struct LineageSourceReadHandle {
    owner: Rc<SourceReadOwner>,
    registration: RegistrationRead,
    provider: kernel::Identity,
    native: kernel::Identity,
    expected_provider: ContentRef,
    expected_native: ContentRef,
}

impl LineageSourceReadHandle {
    /// Compares original owning allocation and registrar identity without authorizing effects.
    pub fn same_original(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.registration.same_original(&other.registration)
    }

    /// Returns the original pre-spawn source reservation identity as data.
    pub fn supervision_id(&self) -> U64 {
        self.owner.identity
    }

    /// Reads the actual private registrar and original live two-group kernel scope.
    ///
    /// No installed callback, command or replacement peer is invoked. Native
    /// dispatch must still use the same SDK lease, whose own registration fence
    /// serializes the real command against connection revocation.
    ///
    /// # Errors
    /// Refuses revoked, transferred, busy or uncertain ownership, a contended or
    /// stale registrar, changed original groups or changed measured executables.
    pub fn ensure_current(&self) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        self.registration.ensure_current()?;
        kernel::verify_identity(self.provider)?;
        kernel::verify_identity(self.native)?;
        kernel::verify_executable(self.provider.pid, &self.expected_provider)?;
        kernel::verify_executable(self.native.pid, &self.expected_native)?;
        self.registration.ensure_current()?;
        self.owner.ensure_current()
    }
}

impl LineageSourceGuard {
    /// Issues a read-only handle from actual attached, pinned original custody.
    ///
    /// Fixed validated content references are retained before a final source
    /// read. Repeated issuance preserves the same original owner and registrar;
    /// independently configured holders must refuse replacement handles.
    ///
    /// # Errors
    /// Refuses absent typed attachment, unresolved native realization, revoked
    /// ownership, changed source identity or unavailable original registration.
    pub fn original_read_handle(&self) -> Result<LineageSourceReadHandle, ProviderError> {
        self.read_owner.ensure_current()?;
        self.verify_extension_registrar()?;
        let custody = self.custody.as_ref().ok_or(ProviderError::Correlation(
            "original source read custody transferred",
        ))?;
        let NativeCustody::Original(native) = custody.native else {
            return Err(ProviderError::Correlation(
                "original native read unresolved",
            ));
        };
        let provider = custody.provider.ok_or(ProviderError::Correlation(
            "original provider read unresolved",
        ))?;
        let controller = custody
            .controller
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original source read controller unavailable",
            ))?;
        let handshake = custody
            .extension_handshake
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original typed read registrar unavailable",
            ))?;
        custody.expected_provider.validate()?;
        custody.expected_native.validate()?;
        let handle = LineageSourceReadHandle {
            owner: Rc::clone(&self.read_owner),
            registration: controller.original_registration_read(handshake)?,
            provider,
            native,
            expected_provider: custody.expected_provider.clone(),
            expected_native: custody.expected_native.clone(),
        };
        handle.ensure_current()?;
        Ok(handle)
    }
}

#[cfg(test)]
#[path = "source_read_tests.rs"]
mod tests;
