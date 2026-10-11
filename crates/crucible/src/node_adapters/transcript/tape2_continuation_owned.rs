//! Retains complete authenticated Tape2 model journals without source path reads.
//!
//! The owned closure comes only from the signed archive source pin. This module
//! validates the same complete consumed-prefix codec before transferring its
//! cursor/journals into model custody. It grants no physical preservation facet.

use super::*;
use crate::node_state::PinnedOriginalLineageSource;

/// Owns original typed source bodies and exact authenticated continuation journals.
///
/// This type has no caller-constructed DTO or public mutable cursor. The original
/// source artifact, FIRST scopes and SOURCE-CAPTURE runtime remain unchanged after
/// the operational and archive namespaces disappear. TARGET still requires an
/// independently qualified owning runtime and genuine producer/consumer hooks.
pub struct PinnedTape2Continuation {
    pub(in crate::node_adapters::transcript) source: Rc<PinnedOriginalLineageSource>,
    pub(in crate::node_adapters::transcript) wire: Rc<Tape2ContinuationWire>,
    pub(in crate::node_adapters::transcript) transcript: Rc<AuthenticatedTranscript>,
}

impl PinnedTape2Continuation {
    /// Borrows immutable original native source body custody.
    pub fn source(&self) -> &PinnedOriginalLineageSource {
        &self.source
    }

    /// Borrows the exact original consumed cutoff, including sticky divergence.
    pub fn cursor(&self) -> &ReplayCursorSnapshot {
        &self.wire.cursor
    }

    /// Borrows original transcript bytes without granting future response authority.
    pub fn transcript(&self) -> &AuthenticatedTranscript {
        &self.transcript
    }

    /// Borrows the preserved source-capture route without reminting owner identities.
    pub fn route(&self) -> &NodeRoute {
        &self.wire.route
    }

    /// Checks actual fresh target journal custody before any lineage installation.
    ///
    /// Complete original source bodies are read from this pin, never from archive
    /// paths. The selected verifier and each actual native endpoint remain required.
    ///
    /// # Errors
    /// Refuses changed complete-world/cut, unsupported installed source policy,
    /// missing original bodies or either actual endpoint's native journal refusal.
    pub fn prepare_target_context(
        &self,
        runtime: &NodeRuntime,
        target: &ActivationRecord,
        verifier: &mut dyn NativeRuntimeContinuationVerifier,
        limits: OriginalLineageRestorationLimits,
    ) -> Result<OriginalLineageRestoration<'_>, RuntimeError> {
        if target.world_binding_hash != self.source.runtime().source_activation.world_binding_hash
            || target.boundary != self.source.runtime().capture_cut
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let context = runtime.prepare_original_lineage_restoration(
            self.source.runtime_reference(),
            self.source.content(),
            self.source.scheduling(),
            target,
            verifier,
            limits,
        )?;
        if context.record() != self.source.runtime() {
            return Err(RuntimeError::InvalidReceipt);
        }
        context.validate_current(runtime)?;
        Ok(context)
    }
}

/// Authenticates owned Tape2 continuation journals beneath one exact source pin.
///
/// This runs the same complete metadata and consumed-prefix checks as the borrowed
/// source reader. No raw transcript, expected reference or mutable cursor can mint
/// the resulting seal. An error leaves the caller's shared source pin intact.
///
/// # Errors
/// Refuses another owner/codec, omitted Runtime7 or original proof roles, changed
/// FIRST/source scopes, future cursor/cache evidence or unsupported controls.
pub fn authenticate_pinned_tape2_continuation(
    source: Rc<PinnedOriginalLineageSource>,
    node: &Id,
) -> Result<PinnedTape2Continuation, OperationFailure> {
    let (wire, transcript) = {
        let original = source.source();
        let checked = authenticate_tape2_continuation(&original, node)?;
        (checked.wire, checked.transcript)
    };
    Ok(PinnedTape2Continuation {
        source,
        wire: Rc::new(wire),
        transcript: Rc::new(transcript),
    })
}
