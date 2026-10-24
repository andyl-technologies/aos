//! Authenticates a genuine native-five birth before installing its immutable codec.

use super::super::{Native5Policy, PacketNative5SourceLaunch};
use super::*;
use crate::transport::original_frames::OriginalFrameReservation;

pub(in crate::reference_packet::service) mod birth;
pub(in crate::reference_packet::service) mod hello_selection;

pub(in super::super) fn accept_complete(
    socket: &Path,
    launch: PacketNative5SourceLaunch,
) -> Result<PacketSourceService, ProviderError> {
    // This immutable cut and the complete inline holder precede every listener,
    // socket and installed verifier callback. Refusal never extracts an error
    // while dropping the original phase owners.
    let mut original = birth::CompleteBirth::new(launch)?;
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| original.prepare(socket)));
    match result {
        Ok(Ok(service)) => Ok(service),
        Ok(Err(error)) => {
            original.error = Some(error);
            original.hold()
        }
        Err(payload) => {
            original.unwind = Some(payload);
            original.hold()
        }
    }
}

struct CompleteVerifier<'a> {
    launch: &'a PacketNative5SourceLaunch,
    selected: &'a IdSet,
}

impl TrustedHandshakeVerifier for CompleteVerifier<'_> {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        _: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installation.measured_implementation != self.launch.selection.provider.implementation
            || result.provider_identity != self.launch.selection.provider
        {
            return Err(ProviderError::Correlation(
                "native5 actual handshake implementation",
            ));
        }
        Ok(())
    }
    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        if manifest != &self.launch.selection.provider
            || features != self.selected
            || !schemas.is_empty()
            || guarantees
                != &self.launch.selection.realization.bindings[0]
                    .compatibility
                    .guarantees_ref
        {
            return Err(ProviderError::Correlation(
                "native5 actual handshake contract",
            ));
        }
        Ok(())
    }
    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        Err(ProviderError::Correlation(
            "native5 resume requires distinct original restoration",
        ))
    }
    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "native5 original connection cannot be substituted",
        ))
    }
}

// Only the retained inherited-channel verifier reaches this owning constructor.
pub(in super::super) fn accept_complete_with_boot(
    socket: &Path,
    launch: PacketNative5SourceLaunch,
    cut: crate::client::OriginalNative5BirthCut,
    boot: Rc<std::cell::RefCell<super::super::ack_emitter::NativeAckBoot>>,
    literals: Rc<std::cell::RefCell<OriginalFrameReservation>>,
) -> Result<PacketSourceService, ProviderError> {
    let mut original = birth::CompleteBirth::from_original_boot(launch, cut, boot, literals);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| original.prepare(socket))) {
        Ok(Ok(service)) => Ok(service),
        Ok(Err(error)) => {
            original.error = Some(error);
            original.hold()
        }
        Err(payload) => {
            original.unwind = Some(payload);
            original.hold()
        }
    }
}
