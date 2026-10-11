//! Consuming typed-Hello attachment with the original pre-reserved process owner.

use crucible_node_provider::{
    ProviderError, client::ReferenceController, handshake::ExtensionHandshake,
};

use super::{CnpLaunchGuard, CnpRegistrar};

/// Retains every original attachment resource after a typed-registration refusal.
pub struct CnpExtensionAttachmentFailure {
    /// Explains refusal without claiming native termination or no prior effects.
    pub error: ProviderError,
    /// Owns the same Child, private directory and pre-reserved supervisor slot.
    pub guard: CnpLaunchGuard,
    /// Owns the original authenticated session and complete control journals.
    pub controller: ReferenceController,
    /// Owns the original typed selection and revocable registration gate.
    pub registrar: ExtensionHandshake,
}

impl CnpLaunchGuard {
    /// Attaches the original typed registrar and controller to this retained Child.
    ///
    /// Consuming the guard permits every refusal to return the same actual
    /// resources. Attachment grants no source, graph or dynamic-input authority.
    ///
    /// # Errors
    /// Returns all owning resources on a foreign process/registrar, revoked lease,
    /// duplicate attachment, missing custody or changed typed selection.
    pub fn attach_extensions(
        mut self,
        controller: ReferenceController,
        registrar: ExtensionHandshake,
    ) -> Result<Self, Box<CnpExtensionAttachmentFailure>> {
        let result = (|| {
            let custody = self
                .custody
                .as_ref()
                .ok_or(ProviderError::Correlation("CNP launch custody transferred"))?;
            if custody.controller.is_some()
                || custody.handshake.is_some()
                || controller.peer_pid() != custody.child.id()
            {
                return Err(ProviderError::Correlation(
                    "typed controller is not original retained Child",
                ));
            }
            controller.verify_extension_registrar(&registrar)
        })();
        if let Err(error) = result {
            return Err(Box::new(CnpExtensionAttachmentFailure {
                error,
                guard: self,
                controller,
                registrar,
            }));
        }
        match self.custody.as_mut() {
            Some(custody) => {
                custody.handshake = Some(CnpRegistrar::Extensions(registrar));
                custody.controller = Some(controller);
                Ok(self)
            }
            None => Err(Box::new(CnpExtensionAttachmentFailure {
                error: ProviderError::Correlation("CNP launch custody transferred"),
                guard: self,
                controller,
                registrar,
            })),
        }
    }
}
