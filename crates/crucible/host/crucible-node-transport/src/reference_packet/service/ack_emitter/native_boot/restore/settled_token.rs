//! Preserves actual verified native token relations as inert graph history.
//!
//! This cannot construct a token or install a historical Connection. The real
//! boot, immutable policy and any retained attempt remain private Rust owners;
//! only their checked historical edges are encoded. Current Capture authorization
//! remains a separate genuine Source/ticket/prepaid native permission.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct TokenHistory<'a>(&'a VerifiedCompleteRestoration);

impl VerifiedCompleteRestoration {
    pub(super) fn authenticate_settled_history_edges_data(&self) -> Result<(), ProviderError> {
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        attempt.ensure_origin()?;
        if owner
            .policy
            .as_ref()
            .is_none_or(|policy| !Rc::ptr_eq(policy, &self.policy))
        {
            return Err(refused());
        }
        self.identity
            .authenticate_settled_history_roots_data(&self.authority, &self.policy)?;
        if owner
            .restoration
            .as_ref()
            .is_none_or(|attempt| !Rc::ptr_eq(attempt, &self.attempt))
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the full token fields after their actual retained edge checks.
    ///
    /// # Errors
    /// Refuses borrowed/foreign boot, another registration/policy, a changed
    /// original or a different retained attempt. No installation grant is made.
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_settled_history_edges_data()?;
        Ok(TokenHistory(self))
    }

    /// Appends token, identity and actual alias edges without payload recursion.
    ///
    /// # Errors
    /// Refuses changed native relations, exhausted admitted banks or checked overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_edges_data()?;
        let Self {
            identity,
            boot,
            policy,
            authority,
            attempt,
        } = self;
        identity.observe_settled_history_metadata_data(observer)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        authority.observe_retained_metadata(observer)?;
        observer.shared_original(
            MetadataSharedKind::NativeRestoreCommitAttempt,
            attempt.as_ref(),
        )
    }

    /// Names the defining token, actual borrowed boot, identity and registrar views.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<TokenHistory<'static>>()
            + size_of::<Result<TokenHistory<'static>, ProviderError>>()
            + size_of::<std::cell::Ref<'static, NativeAckBoot>>()
            + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, std::cell::BorrowError>>()
            + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, ProviderError>>()
            + size_of::<std::cell::Ref<'static, NativeCompleteRestoreAttempt>>()
            + size_of::<Result<std::cell::Ref<'static, NativeCompleteRestoreAttempt>, std::cell::BorrowError>>()
            + size_of::<Option<&Rc<crate::reference_packet::Native5Policy>>>()
            + size_of::<Result<(), ProviderError>>()
            + ConnectionAuthority::settled_history_counter_scratch_data()
            + OriginalNativeRestorationConnectionIdentity::settled_history_counter_scratch_data()
            + field_view_bytes(|value: &'static VerifiedCompleteRestoration| {
                let VerifiedCompleteRestoration {
                    identity,
                    boot,
                    policy,
                    authority,
                    attempt,
                } = value;
                (identity, boot, policy, authority, attempt)
            })
    }
}

impl Serialize for TokenHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_settled_history_edges_data()
            .map_err(serde::ser::Error::custom)?;
        let VerifiedCompleteRestoration {
            identity,
            boot,
            policy,
            authority,
            attempt,
        } = self.0;
        let _ = (boot, policy);
        let identity = identity
            .borrowed_settled_history_data()
            .map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("VerifiedNativeTokenHistory17", 6)?;
        state.serialize_field("schema", "source-private.native-verified-commit-history/17")?;
        state.serialize_field("identity", &identity)?;
        state.serialize_field("boot_role", "native-boot")?;
        state.serialize_field("policy_role", "native-policy")?;
        state.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        let _ = attempt;
        state.serialize_field("attempt_role", "native-complete-restore-commit")?;
        state.end()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}

impl VerifiedCompleteRestoration {
    /// Checks the installed wrapper's same actual retained mapping allocation.
    ///
    /// # Errors
    /// Refuses changed boot/token relations, a borrowed attempt or another map.
    pub(crate) fn authenticate_settled_history_mapping_data(
        &self,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_edges_data()?;
        let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
        attempt.ensure_origin()?;
        if !Rc::ptr_eq(&attempt.mapping, mapping) {
            return Err(refused());
        }
        Ok(())
    }
}
