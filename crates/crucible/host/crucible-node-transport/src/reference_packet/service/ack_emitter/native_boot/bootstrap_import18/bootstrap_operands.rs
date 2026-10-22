//! Lends all four actual ACK normalization preimages under one original cut.
//!
//! The views borrow the original boot, measured image, immutable policy and SDK.
//! Their projections run before allocating any normalized DOM. The caller still
//! admits its actual normalization schedule; neither shapes nor hashes grant
//! Source/Birth funding, a bootstrap ACK, a model or native phase permission.

use super::*;
use crate::reference_packet::service::complete_restore::import18::OriginalImport18DecodedBodyLoans;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18BootstrapTypedBirthView;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapKernelView, PacketNativeImport18BootstrapTypedPolicyView,
    native_import18_bootstrap_kernel_serialization_data,
    native_import18_bootstrap_operands_counter_scratch_data,
};
use crate::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18CurrentRegistrationView, native_import18_current_registration_view_data,
};
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;

/// Borrows the four actual preimages in birth, kernel, policy and native-role order.
pub(in super::super) struct BootstrapAckOperands<'a> {
    /// Borrows the original complete birth association, excluding the signing key.
    pub(in super::super) birth: &'a PacketNativeImport18BootstrapTypedBirthView<'a>,
    /// Borrows the authenticated controller and actual measured native coordinates.
    pub(in super::super) kernel: &'a PacketNativeImport18BootstrapKernelView<'a>,
    /// Borrows the complete immutable policy and current negotiated SDK selection.
    pub(in super::super) policy: &'a PacketNativeImport18BootstrapTypedPolicyView<'a>,
    /// Borrows all nine original current native registration fields.
    pub(in super::super) registration: &'a PacketNativeImport18CurrentRegistrationView<'a>,
}

impl BootstrapAckOperands<'_> {
    /// Projects every preimage before any allocating normalization serializer runs.
    ///
    /// Each result names its independent DOM/JCS, parser/output and formatter
    /// populations. The restriction applies separately to every complete shape;
    /// an enclosing producer must derive and admit the actual combined schedule.
    /// Fixed projection and loan controls have their separate quote below.
    ///
    /// # Errors
    /// Refuses changed field grammar, arithmetic overflow or any complete
    /// component above the independent restriction.
    pub(in super::super) fn serialization_shapes_data(
        &self,
        maximum: usize,
    ) -> Result<[OriginalSerializationStorageData; 4], ProviderError> {
        let Self {
            birth,
            kernel,
            policy,
            registration,
        } = self;
        Ok([
            birth.serialization_data(maximum)?,
            native_import18_bootstrap_kernel_serialization_data(kernel, maximum)?,
            policy.serialization_data(maximum)?,
            registration.native_serialization_data(maximum)?,
        ])
    }
}

impl OriginalImport18RawBootstrap {
    /// Lends all four actual preimages under their original nested terminal guards.
    ///
    /// Completed actual image measurement, immutable policy and live SDK are all
    /// required. Only Copy results escape; no original view or child owner moves.
    /// The same input, process/thread, cut, Hello and SDK checks run around either
    /// callback outcome. Callback allocation remains independently admitted.
    ///
    /// # Errors
    /// Refuses any incomplete original stage, stale custody or SDK, callback
    /// refusal, or any failed terminal guard after inspection.
    pub(in super::super) fn with_bootstrap_ack_operands_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&BootstrapAckOperands<'_>) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_bootstrap_kernel_policy_wire_data(|kernel, policy, authority| {
            let bodies = self.typed_bodies_data()?;
            let birth = bodies.boot.bootstrap_birth_wire_data()?;
            let registration = native_import18_current_registration_view_data(authority, None)?;
            inspect(&BootstrapAckOperands {
                birth: &birth,
                kernel,
                policy,
                registration: &registration,
            })
        })
    }

    /// Names all nested loan, shape and concrete Copy-result controls before entry.
    ///
    /// This quote supplies no inspection budget or live original loan.
    ///
    /// # Errors
    /// Refuses checked control-layout accumulation overflow.
    pub(in super::super) fn bootstrap_ack_operands_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            PacketNativeImport18BootstrapTypedBirthView::counter_scratch_data(),
            PacketNativeImport18CurrentRegistrationView::native_counter_scratch_data(),
            size_of::<OriginalImport18DecodedBodyLoans<'static>>(),
            size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>(),
            native_import18_bootstrap_operands_counter_scratch_data(),
            size_of::<BootstrapAckOperands<'static>>(),
            size_of::<&BootstrapAckOperands<'static>>(),
            size_of::<[OriginalSerializationStorageData; 4]>(),
            size_of::<Result<[OriginalSerializationStorageData; 4], ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<usize>(),
        ]
        .into_iter()
        .try_fold(
            Self::bootstrap_kernel_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(refused),
        )
    }
}
