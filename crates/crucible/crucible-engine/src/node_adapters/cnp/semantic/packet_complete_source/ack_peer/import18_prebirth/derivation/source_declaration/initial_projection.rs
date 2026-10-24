//! Projects native initial demand under the genuine original Source/Birth loan.
//!
//! The returned numeric observation remains DATA in the caller's member. No
//! worker response or Source bank is parsed and no private secret is borrowed.
//! The original typed registration plan supplies the future Host wire fields.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18InitialConstructionData,
    native_import18_initial_construction_counter_scratch_data,
    native_import18_initial_construction_data, native_import18_initial_quote_formatter_data,
};

pub(super) type InitialOperands<'a> = (
    &'a PacketNative5SourceLaunch,
    &'a Id,
    views::RegistrationView<'a>,
);

impl PacketCompleteSemanticSource {
    /// Names fixed original-loan and initial-projection work before its prewalk.
    ///
    /// The caller admits this row before inspecting the actual launch formatters.
    /// Existing Source, completion and private Birth backing stay independently
    /// retained; the projected future native allocations do not occur here.
    pub fn native_import18_initial_projection_counter_data() -> [usize; 3] {
        let [_, transient, scratch] = Self::native_import18_source_declaration_construction_data();
        [
            0,
            transient,
            scratch
                + native_import18_initial_construction_counter_scratch_data()
                + size_of::<views::RegistrationView<'static>>()
                + size_of::<Result<views::RegistrationView<'static>, RuntimeError>>()
                + size_of::<PacketNativeImport18InitialConstructionData>()
                + size_of::<Result<PacketNativeImport18InitialConstructionData, RuntimeError>>()
                + size_of::<&PacketCompleteAckHostRegistrationPlan>()
                + size_of::<Option<&PacketCompleteAckHostRegistrationPlan>>()
                + size_of::<InitialOperands<'static>>()
                + size_of::<Result<InitialOperands<'static>, RuntimeError>>()
                + size_of::<[usize; 3]>() * 2
                + size_of::<Result<[usize; 3], RuntimeError>>()
                + size_of::<usize>(),
        ]
    }

    /// Quotes actual launch formatter work before projecting future native DATA.
    ///
    /// The Host plan contains borrowed identifiers, strings, limits and content
    /// references; it has no custom Bytes formatter. Original guards surround
    /// both successful and refused metadata inspection.
    ///
    /// # Errors
    /// Refuses original Source/Birth/launch custody loss or unsupported metadata.
    pub fn native_import18_initial_projection_prewalk_data(
        &self,
    ) -> Result<[usize; 3], RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let (launch, _, _) = loan.initial_operands()?;
            let mut row = native_import18_initial_quote_formatter_data(launch)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            let [_, transient, scratch] = Self::native_import18_initial_projection_counter_data();
            row[1] = row[1]
                .checked_add(transient)
                .ok_or(RuntimeError::ResourceLimit)?;
            row[2] = row[2]
                .checked_add(scratch)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok(row)
        })();
        let current = loan.authenticate();
        result.and_then(|row| current.map(|()| row))
    }

    /// Projects future native initial demand from this same genuine occurrence.
    ///
    /// Callers first admit the fixed counter and actual formatter prewalk. This
    /// allocation-free walk borrows the actual launch, registration and opaque
    /// Source bank; it creates no Initial, Recipe, escrow or startup permission.
    /// The returned axes describe future native owners, not new parent backing.
    ///
    /// # Errors
    /// Refuses original custody loss, missing planned operands, unsupported
    /// serialization, checked overflow or the independent maximum restriction.
    pub fn native_import18_initial_projection_data(
        &self,
        maximum: usize,
    ) -> Result<PacketNativeImport18InitialConstructionData, RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let (launch, private_launch, registration) = loan.initial_operands()?;
            native_import18_initial_construction_data(
                launch,
                loan.declaration,
                &registration,
                private_launch,
                &launch.controller_executable,
                maximum,
            )
            .map_err(|_| RuntimeError::ResourceLimit)
        })();
        // Even a failed serializer/quote measures the same original terminal
        // custody; preserve the first refusal without releasing the Birth loan.
        let current = loan.authenticate();
        result.and_then(|row| current.map(|()| row))
    }
}

impl OriginalSourceDeclarationLoan<'_> {
    pub(super) fn initial_operands(&self) -> Result<InitialOperands<'_>, RuntimeError> {
        let state = self
            .source
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let launch = state
            .original_launch
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .original();
        let private_launch = state
            .private_launch
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let registration = state
            .registration
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let PacketCompleteAckHostRegistrationPlan {
            connection_id,
            features,
            extensions,
            envelope_extensions,
        } = registration;
        let [binding] = launch.selection.realization.bindings.as_slice() else {
            return Err(RuntimeError::ForeignAuthority);
        };
        Ok((
            launch,
            private_launch,
            views::RegistrationView {
                schema: "source-owned.packet-canonical-ack-registration/5",
                role: "controller",
                connection_id,
                session_id: &binding.authority.session_id,
                incarnation_id: &binding.authority.incarnation_id,
                limits: &launch.limits,
                features,
                extensions,
                envelope_extensions,
            },
        ))
    }
}
