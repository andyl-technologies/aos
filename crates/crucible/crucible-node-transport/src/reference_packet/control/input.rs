//! Original source-owned staging and consumption dispatch for connected edition 4.
//!
//! The source retains the complete native byte journal before publishing an
//! acknowledgement. Uncertainty in response preparation fences the same native
//! original; it never turns a transport ACK into consumption permission.

use super::super::input::PacketInputContext;
use super::*;

impl PacketControl {
    pub(super) fn input(
        &mut self,
        envelope: &Envelope,
        request: InputRequest,
    ) -> Result<PacketControlReply, ProviderError> {
        let context = PacketInputContext::decode(&envelope.extensions)?;
        let active = self.active.as_ref().ok_or(ProviderError::Correlation(
            "packet input requires original activated gate",
        ))?;
        context.authenticate(envelope, &request, &self.selection, active)?;
        if self.current_operation.is_some() {
            return Err(ProviderError::Correlation(
                "packet input overlaps retained execution custody",
            ));
        }
        let NativeProgram::Connected(program) = &mut self.program else {
            return Err(ProviderError::Correlation(
                "packet output-only source has no ingress",
            ));
        };
        // Every action retains at most three complete 64-KiB proof bodies. The
        // conservative complete reservation precedes native journal mutation.
        if self.content.len().saturating_add(3) > OBJECTS
            || self.content_bytes.saturating_add(3 * FRAME) > CONTENT_BYTES
        {
            return Err(ProviderError::ResourceExhausted(
                "packet native input proof closure",
            ));
        }
        let result =
            match &context {
                PacketInputContext::Stage { cut } => {
                    let inventory = self.content.get(&cut.delivery_inventory).ok_or(
                        ProviderError::Correlation("packet original input inventory unavailable"),
                    )?;
                    for event in &request.events {
                        // The installed connected profile has a 32-byte lane;
                        // generic native components may have larger bounds.
                        if event.payload.length.get() > 32 {
                            return Err(ProviderError::ResourceExhausted(
                                "packet connected original lane payload extent",
                            ));
                        }
                        if !self.content.contains_key(&event.payload) {
                            return Err(ProviderError::Correlation(
                                "packet original input payload unavailable",
                            ));
                        }
                    }
                    self.native_effect_attempted = true;
                    program.stage(
                        envelope,
                        &request,
                        &context,
                        &self.selection,
                        active,
                        inventory,
                        &self.content,
                    )?
                }
                PacketInputContext::Commit { .. } => {
                    self.native_effect_attempted = true;
                    program.commit(envelope, &request, &context, &self.selection, active)?
                }
            };
        // The native retained journal remains authoritative if any subsequent
        // allocation, preparation, transfer or acknowledgement fails.
        let result = result.clone();
        for (reference, bytes) in &result.evidence {
            self.install_content(reference.clone(), bytes)?;
        }
        reply(result.result, result.evidence)
    }
}
