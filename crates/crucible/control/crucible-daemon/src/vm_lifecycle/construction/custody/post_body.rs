//! Transfers actual saved postbody obligations after factual body cleanup.
//!
//! The containing canonical driver still destroys its actual body before closing
//! controls. No empty frame or absent obligation proves native World return.

use super::*;

impl crucible_control_api::ProductionVmCleanupOwner for ProductionVmConstructionCustody {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        if !self.physically_closed.load(Ordering::Acquire) {
            return Err(Self::Failure::Retained(
                "construction body cleanup is not complete",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            if self.post_body.is_none() {
                let phase = self.phase.get_mut().map_err(|_| Self::Failure::Poisoned)?;
                let body = match phase {
                    Phase::Partial(partial) => match partial.node_launcher.as_mut() {
                        Some(launcher) => launcher.take_post_body()?,
                        None => None,
                    },
                    Phase::Complete(lifecycle) => {
                        let body = lifecycle.node_launcher.take_post_body()?;
                        body
                    }
                    #[cfg(target_os = "linux")]
                    Phase::Source(source) => source.take_source_retirement_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SharedSource(source) => source.take_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SourceRearmFailure(source) => source.take_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SourcePreparation(preparation) => preparation.take_post_body()?,
                    Phase::Empty => None,
                };
                self.post_body = body;
            }
            if self.first.is_some() && self.post_body.is_none() {
                self.post_body = Some(crate::ProductionVmConstructionPostBody::history_only());
            }
            if let Some(first) = self.first.take() {
                if let Some(body) = self.post_body.as_mut() {
                    if let Err(first) = body.retain_constructor_first(first) {
                        self.first = Some(first);
                        return Err(Self::Failure::Retained(
                            "construction first still occupies its original body",
                        ));
                    }
                } else {
                    self.first = Some(first);
                    return Err(Self::Failure::Retained(
                        "construction history destination is absent",
                    ));
                }
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(destination) = self.return_destination.take() {
            destination.cancel_for_owned_body();
        }
        Ok(self.post_body.take())
    }

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmConstructionCustody::retry_cleanup(self)
    }
}
