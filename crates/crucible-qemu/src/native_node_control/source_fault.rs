//! Original EffectsUnknown diagnostics independent of physical containment.

use crucible_protocol::node_control::{NativeCommandError, SourceFaultFacts};

use super::{NativeQemuControlError, NativeQemuControlTransport};

impl NativeQemuControlTransport {
    /// Returns the immutable original source diagnostic, not physical containment.
    ///
    /// A supervisor must freeze the affected operation's custody and establish
    /// actual containment independently. Historical stops cannot justify fresh
    /// execution or acknowledgement after this diagnostic invalidates the source.
    pub fn source_fault(&self) -> Option<&SourceFaultFacts> {
        self.source_fault.as_ref()
    }

    pub(super) fn accept_source_fault(
        &mut self,
        facts: &SourceFaultFacts,
    ) -> Result<(), NativeQemuControlError> {
        facts.validate()?;
        if facts.prepared_scope_hash != self.prepared_scope_hash
            || self
                .source_fault
                .as_ref()
                .is_some_and(|original| original != facts)
        {
            return Err(NativeCommandError::Conflict.into());
        }
        if facts.command_sequence.get() != 0 {
            let original = self
                .journal
                .original(facts.command_sequence)
                .ok_or(NativeCommandError::Conflict)?;
            if original.identity_digest()? != facts.command_digest {
                return Err(NativeCommandError::Conflict.into());
            }
        }
        self.source_fault = Some(facts.clone());
        Ok(())
    }
}
