//! Address-free JIT module readiness checks.
//!
//! This module composes the verified CLIF artifact layer with the runtime-symbol
//! declaration preflight. It gives the future `JITModule` setup code one checked
//! handoff point for the artifact identity, deterministic function name, and
//! external declarations it would need, while preserving the current blocker:
//! helper wrappers and value-only builtin symbols still have no executable
//! addresses to register.

use std::{error::Error, fmt};

use cranelift_codegen::ir::UserFuncName;

use crate::{
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource},
    symbols::{
        JitRuntimeSymbolDeclaration, JitRuntimeSymbolDeclarationError,
        JitRuntimeSymbolDeclarationGap, jit_runtime_symbol_declaration_preflight,
    },
    tier::JitTier,
};

/// Address-free CLIF artifact metadata needed by future module setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitModuleArtifactMetadata {
    tier: JitTier,
    kind: JitClifArtifactKind,
    source: JitClifArtifactSource,
    function_name: UserFuncName,
}

impl JitModuleArtifactMetadata {
    /// Copies module-relevant metadata from a verified CLIF artifact.
    pub fn from_artifact(artifact: &JitClifArtifact) -> Self {
        Self {
            tier: artifact.tier(),
            kind: artifact.kind(),
            source: artifact.source(),
            function_name: artifact.function_name().clone(),
        }
    }

    /// Returns the JIT tier the artifact is intended to feed.
    pub const fn tier(&self) -> JitTier {
        self.tier
    }

    /// Returns the lowered CLIF body kind.
    pub const fn kind(&self) -> JitClifArtifactKind {
        self.kind
    }

    /// Returns the source identity for the artifact.
    pub const fn source(&self) -> JitClifArtifactSource {
        self.source
    }

    /// Returns the deterministic CLIF function name carried by the artifact.
    pub const fn function_name(&self) -> &UserFuncName {
        &self.function_name
    }
}

/// Address-free readiness report for future Cranelift module setup.
#[derive(Clone, Debug, PartialEq)]
pub struct JitModuleReadinessPreflight {
    artifact: JitModuleArtifactMetadata,
    symbol_declarations: Vec<JitRuntimeSymbolDeclaration>,
    symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
}

impl JitModuleReadinessPreflight {
    fn new(
        artifact: JitModuleArtifactMetadata,
        symbol_declarations: Vec<JitRuntimeSymbolDeclaration>,
        symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
    ) -> Self {
        Self {
            artifact,
            symbol_declarations,
            symbol_gaps,
        }
    }

    /// Returns the artifact metadata that would feed module compilation.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns CLIF external declarations that are currently shape-known.
    pub fn symbol_declarations(&self) -> &[JitRuntimeSymbolDeclaration] {
        &self.symbol_declarations
    }

    /// Returns stable runtime symbols that still block complete module setup.
    pub fn symbol_gaps(&self) -> &[JitRuntimeSymbolDeclarationGap] {
        &self.symbol_gaps
    }

    /// Returns true when all stable runtime symbols have declaration metadata.
    pub fn is_complete(&self) -> bool {
        self.symbol_gaps.is_empty()
    }

    /// Returns the declaration for `symbol_name`, when present.
    pub fn declaration_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolDeclaration> {
        self.symbol_declarations
            .iter()
            .find(|declaration| declaration.symbol_name() == symbol_name)
    }

    /// Returns the module-readiness gap for `symbol_name`, when present.
    pub fn gap_for_symbol(&self, symbol_name: &str) -> Option<&JitRuntimeSymbolDeclarationGap> {
        self.symbol_gaps
            .iter()
            .find(|gap| gap.symbol_name() == symbol_name)
    }
}

/// Complete address-free module setup metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct JitModuleReadinessPlan {
    artifact: JitModuleArtifactMetadata,
    symbol_declarations: Vec<JitRuntimeSymbolDeclaration>,
}

impl JitModuleReadinessPlan {
    /// Converts a complete preflight report into a module-readiness plan.
    ///
    /// # Errors
    ///
    /// Returns [`JitModuleReadinessError::IncompleteRuntimeSymbols`] when
    /// runtime-symbol declaration gaps remain.
    pub fn from_preflight(
        preflight: JitModuleReadinessPreflight,
    ) -> Result<Self, JitModuleReadinessError> {
        if !preflight.symbol_gaps.is_empty() {
            return Err(JitModuleReadinessError::IncompleteRuntimeSymbols { preflight });
        }

        Ok(Self {
            artifact: preflight.artifact,
            symbol_declarations: preflight.symbol_declarations,
        })
    }

    /// Returns the artifact metadata that would feed module compilation.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns CLIF external declarations required by the module.
    pub fn symbol_declarations(&self) -> &[JitRuntimeSymbolDeclaration] {
        &self.symbol_declarations
    }

    /// Returns the declaration for `symbol_name`, when present.
    pub fn declaration_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&JitRuntimeSymbolDeclaration> {
        self.symbol_declarations
            .iter()
            .find(|declaration| declaration.symbol_name() == symbol_name)
    }
}

/// A failure while building address-free module-readiness metadata.
#[derive(Debug)]
pub enum JitModuleReadinessError {
    /// Runtime symbol declarations could not be built.
    SymbolDeclaration(JitRuntimeSymbolDeclarationError),
    /// Runtime symbol declaration gaps still block complete module setup.
    IncompleteRuntimeSymbols {
        /// The preserved readiness report, including declarations and gaps.
        preflight: JitModuleReadinessPreflight,
    },
}

impl fmt::Display for JitModuleReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SymbolDeclaration(error) => write!(formatter, "{error}"),
            Self::IncompleteRuntimeSymbols { preflight } => write!(
                formatter,
                "runtime symbols incomplete: {} gap(s) remain before JIT module setup",
                preflight.symbol_gaps().len()
            ),
        }
    }
}

impl Error for JitModuleReadinessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SymbolDeclaration(error) => Some(error),
            Self::IncompleteRuntimeSymbols { .. } => None,
        }
    }
}

impl From<JitRuntimeSymbolDeclarationError> for JitModuleReadinessError {
    fn from(error: JitRuntimeSymbolDeclarationError) -> Self {
        Self::SymbolDeclaration(error)
    }
}

/// Builds an address-free module-readiness report for `artifact`.
///
/// The report carries the artifact metadata, CLIF declarations for callable
/// builtin symbols, and the stable runtime-symbol gaps that still block complete
/// module setup.
///
/// # Errors
///
/// Returns [`JitModuleReadinessError::SymbolDeclaration`] if runtime-symbol
/// declaration metadata cannot be built.
pub fn jit_module_readiness_preflight_for_artifact(
    artifact: &JitClifArtifact,
) -> Result<JitModuleReadinessPreflight, JitModuleReadinessError> {
    let symbol_preflight = jit_runtime_symbol_declaration_preflight()?;
    Ok(JitModuleReadinessPreflight::new(
        JitModuleArtifactMetadata::from_artifact(artifact),
        symbol_preflight.declarations().to_vec(),
        symbol_preflight.gaps().to_vec(),
    ))
}

/// Builds complete address-free module setup metadata for `artifact`.
///
/// This is a strict gate: it returns a plan only when every stable runtime
/// symbol has declaration metadata. In the current implementation helper symbols
/// and value-only builtins intentionally make this return an incomplete error.
///
/// # Errors
///
/// Returns [`JitModuleReadinessError::SymbolDeclaration`] if runtime-symbol
/// declaration metadata cannot be built. Returns
/// [`JitModuleReadinessError::IncompleteRuntimeSymbols`] while any stable
/// runtime symbol is missing declaration metadata.
pub fn jit_module_readiness_plan_for_artifact(
    artifact: &JitClifArtifact,
) -> Result<JitModuleReadinessPlan, JitModuleReadinessError> {
    let preflight = jit_module_readiness_preflight_for_artifact(artifact)?;
    JitModuleReadinessPlan::from_preflight(preflight)
}

#[cfg(test)]
mod tests {
    use ratchet_core::{
        EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
        syntax::Span,
    };
    use ratchet_value::value::Value;

    use super::*;
    use crate::{
        artifact::{JitClifArtifactKind, JitClifArtifactSource},
        lower::{
            clif_name_for_ir_root, lower_constant_ir_thunk_body_artifact,
            lower_constant_thunk_body_artifact,
        },
        tier::JitTier,
    };

    #[test]
    fn module_readiness_preflight_records_artifact_and_symbols() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::int(42)).expect("constant artifact lowers");
        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");

        assert_eq!(preflight.artifact().tier(), JitTier::Tier1Baseline);
        assert_eq!(preflight.artifact().kind(), JitClifArtifactKind::ThunkBody);
        assert_eq!(
            preflight.artifact().source(),
            JitClifArtifactSource::ConstantSmoke
        );
        assert_eq!(
            preflight.artifact().function_name(),
            &UserFuncName::default()
        );
        assert!(
            preflight
                .declaration_for_symbol("nix.builtin.derivationStrict")
                .is_some()
        );
        assert!(preflight.declaration_for_symbol("aos_env_get").is_some());
        assert!(matches!(
            preflight.gap_for_symbol("aos_force"),
            Some(
                JitRuntimeSymbolDeclarationGap::HelperWithoutCoreCallSignature {
                    role: RuntimeHelperRole::ForcingControl,
                    ..
                }
            )
        ));
        assert!(!preflight.is_complete());
    }

    #[test]
    fn module_readiness_plan_refuses_incomplete_runtime_symbols() {
        let artifact =
            lower_constant_thunk_body_artifact(Value::null()).expect("constant artifact lowers");
        let error = jit_module_readiness_plan_for_artifact(&artifact)
            .expect_err("runtime symbol gaps block complete module setup");

        let JitModuleReadinessError::IncompleteRuntimeSymbols { preflight } = error else {
            panic!("expected incomplete runtime-symbol error");
        };

        assert_eq!(preflight.artifact().kind(), JitClifArtifactKind::ThunkBody);
        assert!(preflight.symbol_declarations().len() > 1);
        assert!(preflight.symbol_gaps().len() > 1);
        assert!(preflight.declaration_for_symbol("aos_force").is_none());
    }

    #[test]
    fn module_readiness_plan_preserves_complete_preflight_metadata() {
        let artifact = lower_constant_thunk_body_artifact(Value::bool(true))
            .expect("constant artifact lowers");
        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");
        let complete = JitModuleReadinessPreflight::new(
            JitModuleArtifactMetadata::from_artifact(&artifact),
            preflight.symbol_declarations().to_vec(),
            Vec::new(),
        );

        let plan = JitModuleReadinessPlan::from_preflight(complete)
            .expect("synthetic complete preflight becomes a plan");

        assert_eq!(
            plan.artifact().source(),
            JitClifArtifactSource::ConstantSmoke
        );
        assert_eq!(
            plan.symbol_declarations().len(),
            preflight.symbol_declarations().len()
        );
        assert_eq!(
            plan.declaration_for_symbol("nix.builtin.derivationStrict")
                .map(JitRuntimeSymbolDeclaration::kind),
            Some(RuntimeSymbolKind::Builtin)
        );
    }

    #[test]
    fn module_artifact_metadata_copies_deterministic_ir_function_name() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Str,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::None,
                ),
                IrNode::new(
                    IrKind::Int,
                    Span::new(4, 5),
                    EffectClass::pure(),
                    IrData::Int(5),
                ),
            ],
            Vec::new(),
        );
        let artifact = lower_constant_ir_thunk_body_artifact(&arena, IrId::new(1))
            .expect("IR root artifact lowers");

        let metadata = JitModuleArtifactMetadata::from_artifact(&artifact);

        assert_eq!(
            metadata.function_name(),
            &clif_name_for_ir_root(IrId::new(1))
        );
    }
}
