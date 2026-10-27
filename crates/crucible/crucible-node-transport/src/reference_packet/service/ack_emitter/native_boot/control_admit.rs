//! Hands the exact installed assigned Admit to its native Control dispatcher.
//!
//! The handoff is a short-lived, non-cloneable owner created only after the
//! installed token authenticates the current pending original. It preserves the
//! signed envelope; generic Control dispatch cannot manufacture this exception.

use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::{
    connection::{Connection, ProviderStream},
    envelope::Method,
};

pub(crate) struct OriginalCanonicalAckControlAdmit<'a> {
    original: &'a Envelope,
    boot: Rc<RefCell<NativeAckBoot>>,
    policy: Rc<crate::reference_packet::Native5Policy>,
    authority: ConnectionAuthority,
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn retain_original_control_admit<'a, S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &'a Envelope,
    ) -> Result<OriginalCanonicalAckControlAdmit<'a>, ProviderError> {
        self.authenticate_installation(connection)?;
        if original != &self.original {
            return Err(refused());
        }
        Ok(OriginalCanonicalAckControlAdmit {
            original,
            boot: Rc::clone(&self.boot),
            policy: Rc::clone(&self.policy),
            authority: self.authority.clone(),
        })
    }
}

impl OriginalCanonicalAckControlAdmit<'_> {
    pub(crate) fn authenticate_request(
        &self,
        original: &Envelope,
        selection: &PacketControlSelection,
    ) -> Result<(), ProviderError> {
        self.authority.ensure_live()?;
        let boot = self
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native ACK Control boot borrowed"))?;
        boot.ensure_origin()?;
        if !std::ptr::eq(original, self.original)
            || original.method != Method::Admit
            || original.extensions.len() != 1
            || !boot.verified
            || boot.original.as_ref() != Some(original)
            || boot
                .policy
                .as_ref()
                .is_none_or(|policy| !Rc::ptr_eq(policy, &self.policy))
        {
            return Err(refused());
        }
        self.policy
            .authenticate_original_control_selection(selection)?;
        let proof = original
            .extensions
            .get(PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
            .ok_or_else(refused)?;
        validate_proof_value(proof)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native ACK Control handoff differs")
}
