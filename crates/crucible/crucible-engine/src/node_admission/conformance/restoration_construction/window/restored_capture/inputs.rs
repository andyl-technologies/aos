//! Lends current Capture custody without recasting its imported archive family.
//!
//! The Window alone constructs this callback view after authenticating the real
//! installed member. Imported owners are historical DATA; current SourceRead,
//! administrative ticket and separately admitted Capture rows remain required.

use super::*;
use crate::node_adapters::cnp::{
    CnpSemanticSource, OriginalRestoredSettledColdOwnerView, PacketCompleteSemanticSource,
};
use crate::node_admission::conformance::restoration_construction::observation::OriginalInstalledRestorationObservationSigningInputs;
use crate::node_contract::OriginalLineageNativeScope;
use crate::node_state::{CompleteOriginalNativeTicket, CompleteOriginalRestorationSource};

/// Distinguishes the actual signed input family from future Capture capability.
///
/// Initial invocation imports retain their genuine old reader loan. A current17
/// import lends its distinct sealed native and current Host17 owners. Neither
/// branch changes the imported key or constructs an old ColdGroup from new DATA.
pub(crate) enum OriginalRestoredCaptureImportedOwnerInputs<'a> {
    InitialInvocation15(&'a OriginalInstalledRestorationObservationSigningInputs<'a>),
    Settled17(OriginalRestoredSettledColdOwnerView<'a>),
}

/// Borrows the same current Window, World and Source during a Capture callback.
///
/// This is not a capture permit, archive decoder or authority constructor. The
/// Source retains its actual completed Commit/Hold/World, first observation and
/// current checkpoint. The private claim separately binds its administrative
/// ticket and both runtime-object identities before any SDK effect.
pub(crate) struct OriginalRestoredCaptureSigningInputs<'a> {
    pub(super) window: &'a CompleteOriginalRestorationWindow,
    pub(super) selected: usize,
    pub(crate) source: &'a PacketCompleteSemanticSource,
    pub(crate) archive: &'a CompleteOriginalRestorationSource,
    pub(crate) ticket: &'a CompleteOriginalNativeTicket,
    pub(crate) plan: &'a InstalledConformancePlan,
    pub(crate) world: &'a WorldActivation,
    pub(crate) scope: &'a OriginalLineageNativeScope,
    pub(crate) scope_proof: &'a ContentRef,
    pub(crate) scope_proof_body: &'a [u8],
    pub(crate) historical: OriginalRestoredCaptureImportedOwnerInputs<'a>,
}

impl OriginalRestoredCaptureSigningInputs<'_> {
    /// Rechecks the registered member without reopening Source or SDK owners.
    ///
    /// # Errors
    /// Refuses foreign Source, plan, World or member identity, missing installed
    /// context, an inactive Capture gate or a revoked retained runtime fence.
    pub(crate) fn authenticate_current_data(&self) -> Result<(), RuntimeError> {
        self.window
            .authenticate_restored_capture_signing_member_data(
                self.selected,
                self.source,
                self.plan,
                self.world,
                self.scope,
            )
    }

    /// Borrows independently validated import geometry from this exact ticket.
    ///
    /// # Errors
    /// Refuses an unauthenticated current member or a missing actual import row.
    /// This loan neither reconstructs a native demand nor renews native credit.
    pub(crate) fn native_import_geometry_data(
        &self,
    ) -> Result<
        &crucible_node_transport::protocol_snapshot::restored_settled17::RestoredSettledNativeImportGeometryData,
        RuntimeError,
    >{
        self.authenticate_current_data()?;
        self.ticket.original_restored_settled_import_geometry_data()
    }

    /// Borrows the genuine fresh activation independently of the imported cut.
    pub(crate) fn activation_data(&self) -> &crate::node_contract::ActivationRecord {
        &self.scope.target
    }
}

impl CompleteOriginalRestorationWindow {
    /// Lends a Capture view from the actual imported historical family.
    ///
    /// The initial15 branch borrows its original completed observation owner;
    /// it never manufactures that owner from current17 metadata. Current17 is
    /// deliberately unavailable until the separate whole cold-owner join has
    /// completed and can lend its own sealed historical owners.
    ///
    /// # Errors
    /// Refuses a foreign retained Source, signed family, proof identity, World
    /// or member, or an unavailable distinct current17 cold-owner constructor.
    pub(crate) fn with_original_restored_capture_signing_inputs_data<R>(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        proof_identity: [u8; 32],
        inspect: impl FnOnce(&OriginalRestoredCaptureSigningInputs<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.origin()?;
        let actual = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !std::ptr::eq(actual.as_ref(), source)
            || proof_identity != self.original_complete_scope_proof_identity_data()?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let installed = source.installation();
        let mut owners = self
            .archive
            .archive()
            .owners()
            .iter()
            .filter(|owner| owner.owner == installed.owner.owner.id);
        let owner = owners.next().ok_or(RuntimeError::ForeignAuthority)?;
        if owners.next().is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let family = source
            .supported_complete_historical_archive_family_data(&owner.key)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        match family {
            crate::node_adapters::cnp::CompleteHistoricalArchiveFamily::InitialInvocation15 => {
                let mut result = None;
                self.with_original_observation_signing_inputs_data(
                    selected,
                    source,
                    proof_identity,
                    |observation| {
                        let activation = observation.activation;
                        let world = activation.world.ok_or(RuntimeError::NotActivated)?;
                        let inputs = OriginalRestoredCaptureSigningInputs {
                            window: self,
                            selected,
                            source,
                            archive: activation.transfer.archive,
                            ticket: activation.transfer.ticket,
                            plan: activation.transfer.plan,
                            world,
                            scope: activation.scope,
                            scope_proof: activation.scope_proof,
                            scope_proof_body: activation.scope_proof_body,
                            historical:
                                OriginalRestoredCaptureImportedOwnerInputs::InitialInvocation15(
                                    observation,
                                ),
                        };
                        inputs.authenticate_current_data()?;
                        result = Some(inspect(&inputs)?);
                        inputs.authenticate_current_data()
                    },
                )?;
                result.ok_or(RuntimeError::OwnerUnavailable)
            }
            crate::node_adapters::cnp::CompleteHistoricalArchiveFamily::Settled17 => {
                Err(RuntimeError::UnsupportedFacet)
            }
        }
    }
}
