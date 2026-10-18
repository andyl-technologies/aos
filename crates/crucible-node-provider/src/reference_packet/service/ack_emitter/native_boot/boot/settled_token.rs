//! Preserves actual verified native token relations as inert graph history.
//!
//! This cannot construct a token or install a historical Connection. The real
//! boot, immutable policy and any retained attempt remain private Rust owners;
//! only their checked historical edges are encoded. Current Capture authorization
//! remains a separate genuine Source/ticket/prepaid native permission.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct TokenHistory<'a>(&'a VerifiedCanonicalAckAdmission);

impl VerifiedCanonicalAckAdmission {
    fn authenticate_settled_history_edges_data(&self) -> Result<(), ProviderError> {
        let owner = self.boot.try_borrow().map_err(|_| refused())?;
        owner.ensure_origin()?;
        if owner
            .policy
            .as_ref()
            .is_none_or(|policy| !Rc::ptr_eq(policy, &self.policy))
        {
            return Err(refused());
        }
        self.identity
            .authenticate_settled_history_roots_data(&self.authority, &self.policy)?;
        if !owner.verified || owner.original.as_ref() != Some(&self.original) {
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
            original,
        } = self;
        identity.observe_settled_history_metadata_data(observer)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        authority.observe_retained_metadata(observer)?;
        observer.observe(original)
    }

    /// Names the defining token, actual borrowed boot, identity and registrar views.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<TokenHistory<'static>>()
            + size_of::<Result<TokenHistory<'static>, ProviderError>>()
            + size_of::<std::cell::Ref<'static, NativeAckBoot>>()
            + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, std::cell::BorrowError>>()
            + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, ProviderError>>()
            + size_of::<Option<&Rc<crate::reference_packet::Native5Policy>>>()
            + size_of::<Result<(), ProviderError>>()
            + ConnectionAuthority::settled_history_counter_scratch_data()
            + crate::connection::OriginalNativeAckConnectionIdentity::settled_history_counter_scratch_data()
            + field_view_bytes(|value: &'static VerifiedCanonicalAckAdmission| {
                let VerifiedCanonicalAckAdmission { identity, boot, policy, authority, original } = value;
                (identity, boot, policy, authority, original,)
            })
    }
}

impl Serialize for TokenHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_settled_history_edges_data()
            .map_err(serde::ser::Error::custom)?;
        let VerifiedCanonicalAckAdmission {
            identity,
            boot,
            policy,
            authority,
            original,
        } = self.0;
        let _ = (boot, policy);
        let identity = identity
            .borrowed_settled_history_data()
            .map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("VerifiedNativeTokenHistory17", 6)?;
        state.serialize_field("schema", "source-private.native-verified-admit-history/17")?;
        state.serialize_field("identity", &identity)?;
        state.serialize_field("boot_role", "native-boot")?;
        state.serialize_field("policy_role", "native-policy")?;
        state.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        state.serialize_field("original", original)?;
        state.end()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native ACK token historical edges differ")
}
