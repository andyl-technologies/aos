//! Binds a fresh Source template to the original sealed installed mechanism.
//!
//! This stage retains the same deployment owner, never its copied binding DATA.
//! Export, child execution, result acceptance and complete selected Source census
//! remain unavailable until the separate original-job join is supplied.

use super::*;

// These fixed layouts describe the new actual handle/view boundary only. The
// original mechanism payload is preexisting deployment-owned; Rc::clone adds no
// allocation, and opaque L2/runtime storage stays under its real supervisor.
pub(super) const GATE_CONTROLS: usize =
    size_of::<&Option<Rc<VerifiedSourceBirthMechanism>>>() + size_of::<bool>();

pub(super) const BRIDGE_CONTROLS: usize = GATE_CONTROLS
    + size_of::<&Rc<VerifiedSourceBirthMechanism>>() * 2
    + size_of::<Option<&Rc<VerifiedSourceBirthMechanism>>>() * 2
    + size_of::<*const VerifiedSourceBirthMechanism>() * 2
    + size_of::<Option<*const VerifiedSourceBirthMechanism>>() * 2
    + size_of::<Rc<VerifiedSourceBirthMechanism>>() * 2
    + size_of::<Option<Rc<VerifiedSourceBirthMechanism>>>() * 2
    + size_of::<&OriginalNativeSourceTemplate18ConstructionData>() * 2
    + size_of::<&mut OriginalNativeSourceTemplate18Attempt>() * 2
    + size_of::<OriginalNativeSourceTemplate18ConstructionData>()
    + size_of::<OriginalNativeSourceTemplate18MechanismQuote>() * 2
    + size_of::<&OriginalNativeSourceTemplate18MechanismQuote>()
    + size_of::<Result<OriginalNativeSourceTemplate18MechanismQuote, RuntimeError>>()
    + size_of::<Result<OriginalNativeSourceTemplate18ConstructionData, RuntimeError>>()
    + size_of::<Result<(), RuntimeError>>();

/// Retains the exact quoted mechanism through fresh Source construction.
///
/// This quote owns the original sealed deployment Rc, so dropping the
/// caller's handle cannot permit address-reuse rebinding. Its numeric request
/// is DATA only: the installed caller separately admits the original Source
/// allocation and this quote creates no job, process or native permission.
/// It does not implement Clone and exposes no copied-row adoption constructor.
///
/// The caller must independently retain the original code Source through the
/// entire quotation-to-construction interval. This quote retains the mechanism;
/// its code address does not establish a standalone stale-address epoch.
///
/// ```compile_fail
/// use crucible_engine::node_adapters::cnp::OriginalNativeSourceTemplate18MechanismQuote;
/// fn cannot_clone_original_quote(row: OriginalNativeSourceTemplate18MechanismQuote) {
///     let _copy = row.clone();
/// }
/// ```
#[must_use = "retain the original selected quote through construction or refusal"]
pub struct OriginalNativeSourceTemplate18MechanismQuote {
    construction: OriginalNativeSourceTemplate18ConstructionData,
    mechanism: Rc<VerifiedSourceBirthMechanism>,
}

impl OriginalNativeSourceTemplate18MechanismQuote {
    /// Returns the original Source copy's retained, transient and fixed request.
    pub const fn requested_storage_data(&self) -> (usize, usize, usize) {
        self.construction.requested_storage_data()
    }
}

impl PacketCompleteSemanticSource {
    /// Quotes a fresh template retaining the same verified deployment owner.
    ///
    /// The original owner authenticates process enforcement and opened program
    /// guards before any declaration clone. Its copied hashes cannot select this
    /// route. The caller must keep this original code Source strongly retained
    /// until construction finishes; process/thread identity and a
    /// copied code address cannot replace that lifetime precondition.
    /// The caller separately admits the quote before construction; no
    /// Source export, process reservation or execution follows from it.
    ///
    /// # Errors
    /// Refuses revoked deployment, foreign/busy/non-code templates, incomplete
    /// declarations, arithmetic overflow or the original memory restriction.
    ///
    /// ```compile_fail
    /// use crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource;
    /// use crucible_engine::node_adapters::cnp::source_birth_derivation::installation::SourceBirthInstallationBindings;
    /// use std::rc::Rc;
    /// fn cannot_select_from_data(source: &Rc<PacketCompleteSemanticSource>, bindings: SourceBirthInstallationBindings) {
    ///     let _ = source.native_source_template18_with_derivation_construction_data(&bindings, usize::MAX);
    /// }
    /// ```
    pub fn native_source_template18_with_derivation_construction_data(
        self: &Rc<Self>,
        mechanism: &Rc<VerifiedSourceBirthMechanism>,
        maximum: usize,
    ) -> Result<OriginalNativeSourceTemplate18MechanismQuote, RuntimeError> {
        mechanism.authenticate_current()?;
        let mut row = self.native_source_template18_construction_data(maximum)?;
        row.mechanism = Some(Rc::as_ptr(mechanism));
        // The actual clone/Some/field owning windows are distinct from the
        // existing Source/Rc constructor windows. No shared payload is copied.
        row.transient = sum(
            [
                row.transient,
                size_of::<Rc<VerifiedSourceBirthMechanism>>() * 2,
                size_of::<Option<Rc<VerifiedSourceBirthMechanism>>>() * 2,
            ],
            maximum,
        )?;
        sum([row.retained, row.transient, row.scratch], maximum)?;
        // Keep the actual original alive between quote and constructor. A raw
        // address alone could be recycled after its Rc was dropped.
        Ok(OriginalNativeSourceTemplate18MechanismQuote {
            construction: row,
            mechanism: Rc::clone(mechanism),
        })
    }

    /// Retains the quoted original mechanism in a distinct fresh Source once.
    ///
    /// The owner is retained before lineage effects, including on later failed
    /// construction. Old ordinary/native/import/capture routes remain stopped
    /// for the selected Source. Its complete selected census is unresolved, so
    /// this stage cannot enter the current Daemon's complete admission path.
    ///
    /// # Errors
    /// Refuses repeated attempts, a different code/creator/mechanism, revoked
    /// original controls, incomplete declarations or actual lineage refusal.
    /// Every post-output failure retains that same Source and mechanism.
    pub fn native_source_template18_with_derivation_into(
        self: &Rc<Self>,
        row: &OriginalNativeSourceTemplate18MechanismQuote,
        output: &mut OriginalNativeSourceTemplate18Attempt,
    ) -> Result<(), RuntimeError> {
        self.native_source_template18_inner_into(&row.construction, Some(&row.mechanism), output)
    }
}

#[cfg(test)]
#[path = "mechanism/tests.rs"]
mod tests;
