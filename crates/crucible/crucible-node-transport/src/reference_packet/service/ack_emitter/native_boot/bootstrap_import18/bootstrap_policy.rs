//! Lends actual model-absent policy operands for bootstrap ACK normalization.
//!
//! The original typed Source binding, same shared policy and current SDK stay
//! in their real owners. This Copy-only loan builds no intermediate DOM, copies
//! no recipe bank and issues no ACK, native phase or Source/Birth permission.

use super::*;
use crate::handshake::ConnectionAuthority;
use crate::reference_packet::service::complete_restore::import18::OriginalImport18DecodedBodyLoans;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapTypedPolicyView, native_import18_bootstrap_typed_policy_wire_data,
};

impl OriginalImport18RawBootstrap {
    /// Lends the normalized policy preimage under original policy and SDK guards.
    ///
    /// The caller separately admits the returned view's projection/formatter,
    /// DOM/JCS and inspection work before executing it. Complete original input,
    /// policy, literal Hello and SDK guards run around either callback outcome.
    /// Only Copy DATA can escape; no original owner moves or becomes a live grant.
    ///
    /// # Errors
    /// Refuses incomplete policy, stale original custody/cut/SDK/publication,
    /// changed recipe/definitions, callback failure or failed terminal guards.
    pub(in super::super) fn with_bootstrap_policy_wire_data<R: Copy>(
        &self,
        inspect: impl FnOnce(
            &PacketNativeImport18BootstrapTypedPolicyView<'_>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_bootstrap_policy_authority_wire_data(|policy, _| inspect(policy))
    }

    /// Lends the policy and its same actual SDK authority inside one original guard.
    ///
    /// Composite serializers reuse this existing guarded authority instead of
    /// reopening the full SDK custody chain for its already borrowed children.
    ///
    /// # Errors
    /// Preserves the policy loan's original, callback and terminal refusals.
    pub(super) fn with_bootstrap_policy_authority_wire_data<R: Copy>(
        &self,
        inspect: impl FnOnce(
            &PacketNativeImport18BootstrapTypedPolicyView<'_>,
            &ConnectionAuthority,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_immutable_policy_data(|policy| {
            self.with_hello_authority_data(|authority| {
                let bodies = self.typed_bodies_data()?;
                let [import, stage, record] = policy.definitions_data()?;
                let view = native_import18_bootstrap_typed_policy_wire_data(
                    bodies.boot.source_binding_data(),
                    policy.recipe_identity_data(),
                    import,
                    stage,
                    record,
                    authority,
                )?;
                inspect(&view, authority)
            })
        })
    }

    /// Quotes fixed original guards and view controls for the concrete Copy result.
    ///
    /// Dynamic callback/projection/serializer backing remains separately admitted.
    /// This quote changes no initial row and supplies no credit or policy loan.
    ///
    /// # Errors
    /// Refuses checked composition overflow for the actual returned result layout.
    pub(in super::super) fn bootstrap_policy_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            Self::hello_authority_loan_counter_scratch_data::<R>(),
            PacketNativeImport18BootstrapTypedPolicyView::counter_scratch_data(),
            size_of::<OriginalImport18DecodedBodyLoans<'static>>(),
            size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>(),
            size_of::<[&crucible_node_format::SchemaRef; 3]>(),
            size_of::<Result<[&crucible_node_format::SchemaRef; 3], ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<&ConnectionAuthority>(),
        ]
        .into_iter()
        .try_fold(
            Self::immutable_policy_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(refused),
        )
    }
}
