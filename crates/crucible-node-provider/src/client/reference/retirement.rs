//! Writes the owning controller's complete private originals after terminal audit.

use std::io::Write;

use crate::{
    ProviderError,
    bodies::{ResponseShape, decode_request, decode_response},
    envelope::RequestOrigin,
};

use super::ReferenceController;

impl ReferenceController {
    /// Writes complete private original journals without conferring release authority.
    ///
    /// This data includes bootstrap secrets and must only enter a private
    /// operational custody sink. Any accepted or uncertain original remains
    /// under its existing owner and refuses this completed-control export.
    ///
    /// # Errors
    /// Refuses incomplete, uncertain, foreign or nonterminal originals and
    /// unfinished content transfers. Propagates serialization and sink failures.
    pub fn write_retirement_originals(&self, output: &mut impl Write) -> Result<(), ProviderError> {
        if self.observer.is_some() || self.transmissions.is_some() || self.conflicts.is_some() {
            return Err(ProviderError::Correlation(
                "qualification journals require their owning resolver",
            ));
        }
        for original in self.custody.originals() {
            let response = original
                .response
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original control response remains uncertain",
                ))?;
            let request = decode_request(original.request.method, &original.request.body)?;
            let response = decode_response(&request, &response.body)?;
            let terminal = matches!(response.shape, ResponseShape::Completed { .. });
            if !terminal {
                return Err(ProviderError::Correlation(
                    "original control effect remains unresolved",
                ));
            }
        }
        let objects = self.custody.content().retirement_objects()?;
        serde_json::to_writer(
            output,
            &(
                &self.bootstrap,
                self.profile
                    .content_objects()
                    .iter()
                    .map(|object| (&object.reference, &object.bytes))
                    .collect::<Vec<_>>(),
                &self.qualifications,
                self.custody
                    .originals_by_origin(RequestOrigin::Controller)
                    .collect::<Vec<_>>(),
                self.custody
                    .originals_by_origin(RequestOrigin::Provider)
                    .collect::<Vec<_>>(),
                objects,
            ),
        )
        .map_err(crucible_node_contract::ContractError::from)?;
        Ok(())
    }
}
