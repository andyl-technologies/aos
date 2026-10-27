//! Derives launch commitments under the actual original Source and Birth loan.
//!
//! The parent admits original-loan, formatter and canonical construction windows
//! in that order. The opaque fixed output remains DATA; it creates no Recipe,
//! Initial, native phase, private key copy or serialized worker-response view.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18LaunchIdentityData, derive_native_import18_launch_identity_data,
    native_import18_launch_identity_construction_data,
    native_import18_launch_identity_counter_scratch_data,
    native_import18_launch_identity_projection_data,
};

type LaunchOperands<'a> = (&'a PacketNative5SourceLaunch, &'a Id);

impl PacketCompleteSemanticSource {
    /// Names original-loan and fixed launch-identity controls before any prewalk.
    pub fn native_import18_original_launch_identity_counter_data() -> [usize; 3] {
        let [_, transient, scratch] = Self::native_import18_source_declaration_construction_data();
        [
            0,
            transient,
            scratch
                + native_import18_launch_identity_counter_scratch_data()
                + size_of::<LaunchOperands<'static>>()
                + size_of::<Result<LaunchOperands<'static>, RuntimeError>>()
                + size_of::<PacketNativeImport18LaunchIdentityData>()
                + size_of::<Result<PacketNativeImport18LaunchIdentityData, RuntimeError>>()
                + size_of::<[usize; 3]>() * 2
                + size_of::<Result<[usize; 3], RuntimeError>>()
                + size_of::<(usize, usize)>()
                + size_of::<Result<(usize, usize), RuntimeError>>()
                + size_of::<usize>(),
        ]
    }

    /// Prices actual original launch formatters before the canonical quote.
    ///
    /// # Errors
    /// Refuses original custody loss, unavailable planned operands, metadata
    /// traversal or checked arithmetic overflow.
    pub fn native_import18_original_launch_identity_prewalk_data(
        &self,
    ) -> Result<[usize; 3], RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let (launch, _) = loan.launch_identity_operands()?;
            let (formatter, _) = native_import18_launch_identity_projection_data(launch)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            let [_, transient, scratch] =
                Self::native_import18_original_launch_identity_counter_data();
            Ok([
                0,
                formatter
                    .checked_add(transient)
                    .ok_or(RuntimeError::ResourceLimit)?,
                scratch,
            ])
        })();
        let current = loan.authenticate();
        result.and_then(|row| current.map(|()| row))
    }

    /// Quotes full canonical construction from the same original operands.
    ///
    /// The original loan and its actual formatter prewalk precede this quote.
    /// Existing Source, original launch, worker and Birth backing stay retained.
    ///
    /// # Errors
    /// Refuses original custody loss, unsupported serialization, overflow or
    /// construction beyond the independent restriction.
    pub fn native_import18_original_launch_identity_construction_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let (launch, _) = loan.launch_identity_operands()?;
            let (temporary, _) = native_import18_launch_identity_construction_data(launch, maximum)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            let [_, transient, scratch] =
                Self::native_import18_original_launch_identity_counter_data();
            let transient = temporary
                .checked_add(transient)
                .ok_or(RuntimeError::ResourceLimit)?;
            if transient
                .checked_add(scratch)
                .is_none_or(|peak| peak > maximum)
            {
                return Err(RuntimeError::ResourceLimit);
            }
            Ok([0, transient, scratch])
        })();
        let current = loan.authenticate();
        result.and_then(|row| current.map(|()| row))
    }

    /// Derives fixed commitments from this genuine original launch and private-launch ID.
    ///
    /// Callers first admit the defining full construction row. The canonical
    /// construction owners are transient. The returned fixed DATA grants no
    /// Source purpose or opaque Recipe/Initial; worker response bytes stay opaque.
    ///
    /// # Errors
    /// Refuses original Source/Birth/launch custody loss, absent operands or
    /// canonical encoding beyond the independent restriction.
    pub fn derive_native_import18_original_launch_identity_data(
        &self,
        maximum_encoded_bytes: usize,
    ) -> Result<PacketNativeImport18LaunchIdentityData, RuntimeError> {
        let loan = self.original_source_declaration_loan()?;
        let result = (|| {
            let (launch, private_launch) = loan.launch_identity_operands()?;
            derive_native_import18_launch_identity_data(
                launch,
                private_launch,
                maximum_encoded_bytes,
            )
            .map_err(|_| RuntimeError::ResourceLimit)
        })();
        let current = loan.authenticate();
        result.and_then(|identity| current.map(|()| identity))
    }
}

impl OriginalSourceDeclarationLoan<'_> {
    fn launch_identity_operands(&self) -> Result<LaunchOperands<'_>, RuntimeError> {
        let state = self
            .source
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let original = state
            .original_launch
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let private_launch = state
            .private_launch
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        Ok((original.original(), private_launch))
    }
}
