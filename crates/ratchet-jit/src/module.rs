//! Address-free JIT module readiness checks.
//!
//! This module composes the verified CLIF artifact layer with the runtime-symbol
//! declaration preflight. It gives the future `JITModule` setup code one checked
//! handoff point for the artifact identity, deterministic function name, and
//! external declarations it would need, while preserving the current blocker:
//! helper wrappers and value-only builtin symbols still have no executable
//! addresses to register.

use crate::{
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource, JitValueAbi},
    lower::{
        AOS_ALLOC_CONS_FUNCTION_INDEX, AOS_APPLY_FUNCTION_INDEX, AOS_DEOPT_FUNCTION_INDEX,
        AOS_ENV_GET_FUNCTION_INDEX, AOS_FORCE_FUNCTION_INDEX, AOS_HAS_ATTR_FUNCTION_INDEX,
        AOS_JIT_STACK_MAP_ENTER_FUNCTION_INDEX, AOS_JIT_STACK_MAP_EXIT_FUNCTION_INDEX,
        AOS_PRIMOP_CALL_FUNCTION_INDEX, AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        AOS_SELECT_IC_FUNCTION_INDEX, AOS_STRING_LENGTH_FUNCTION_INDEX, AOS_UPDATE_FUNCTION_INDEX,
        AOS_UPVAL_GET_FUNCTION_INDEX,
    },
    symbols::{
        JitRuntimeSymbolDeclaration, JitRuntimeSymbolDeclarationError,
        JitRuntimeSymbolDeclarationGap, jit_runtime_symbol_declaration_preflight,
    },
    tier::JitTier,
};
use cranelift_codegen::ir::{ExternalName, Function, UserExternalName, UserFuncName};
use std::{error::Error, fmt};
const AOS_ENV_GET_SYMBOL: &str = "aos_env_get";
const AOS_ALLOC_CONS_SYMBOL: &str = "aos_alloc_cons";
const AOS_FORCE_SYMBOL: &str = "aos_force";
const AOS_APPLY_SYMBOL: &str = "aos_apply";
const AOS_HAS_ATTR_SYMBOL: &str = "aos_has_attr";
const AOS_SELECT_IC_SYMBOL: &str = "aos_select_ic";
const AOS_UPDATE_SYMBOL: &str = "aos_update";
const AOS_DEOPT_SYMBOL: &str = "aos_deopt";
const AOS_UPVAL_GET_SYMBOL: &str = "aos_upval_get";
const AOS_PRIMOP_CALL_SYMBOL: &str = "aos_primop_call";
const AOS_STRING_LENGTH_SYMBOL: &str = "aos_string_length";
const AOS_JIT_STACK_MAP_ENTER_SYMBOL: &str = "aos_jit_stack_map_enter";
const AOS_JIT_STACK_MAP_EXIT_SYMBOL: &str = "aos_jit_stack_map_exit";
/// Address-free CLIF artifact metadata needed by future module setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitModuleArtifactMetadata {
    tier: JitTier,
    kind: JitClifArtifactKind,
    source: JitClifArtifactSource,
    value_abi: JitValueAbi,
    function_name: UserFuncName,
}

/// A runtime helper or builtin imported by one verified CLIF artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitModuleArtifactRuntimeImport {
    symbol_name: String,
    user_external_name: UserExternalName,
}
impl JitModuleArtifactRuntimeImport {
    fn new(symbol_name: String, user_external_name: UserExternalName) -> Self {
        Self {
            symbol_name,
            user_external_name,
        }
    }

    /// Returns the stable runtime symbol required by the artifact body.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the Cranelift user-external name used by the artifact body.
    pub const fn user_external_name(&self) -> &UserExternalName {
        &self.user_external_name
    }
}

/// A runtime import in one artifact that cannot yet be tied to declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JitModuleArtifactRuntimeImportGap {
    /// The artifact imported an external name outside the known AOS runtime map.
    UnknownExternalName {
        /// The best-effort display form of the CLIF external name.
        display_name: String,
    },
    /// The artifact imported a known runtime symbol with no CLIF declaration.
    MissingDeclaration {
        /// The stable runtime symbol required by the artifact body.
        symbol_name: String,
        /// The Cranelift user-external name used by the artifact body.
        user_external_name: UserExternalName,
    },
    /// The artifact import signature disagrees with the runtime declaration.
    SignatureMismatch {
        /// The stable runtime symbol required by the artifact body.
        symbol_name: String,
        /// The Cranelift user-external name used by the artifact body.
        user_external_name: UserExternalName,
    },
    /// The artifact referenced an imported function without signature metadata.
    MissingImportSignature {
        /// The stable runtime symbol required by the artifact body.
        symbol_name: String,
        /// The Cranelift user-external name used by the artifact body.
        user_external_name: UserExternalName,
    },
}

impl JitModuleArtifactRuntimeImportGap {
    /// Returns the stable runtime symbol name when the gap reached symbol resolution.
    pub fn symbol_name(&self) -> Option<&str> {
        match self {
            Self::UnknownExternalName { .. } => None,
            Self::MissingDeclaration { symbol_name, .. }
            | Self::SignatureMismatch { symbol_name, .. }
            | Self::MissingImportSignature { symbol_name, .. } => Some(symbol_name),
        }
    }
}

impl JitModuleArtifactMetadata {
    /// Copies module-relevant metadata from a verified CLIF artifact.
    pub fn from_artifact(artifact: &JitClifArtifact) -> Self {
        Self {
            tier: artifact.tier(),
            kind: artifact.kind(),
            source: artifact.source(),
            value_abi: artifact.value_abi(),
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

    /// Returns the by-value representation used by the artifact boundary.
    pub const fn value_abi(&self) -> JitValueAbi {
        self.value_abi
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
    artifact_runtime_imports: Vec<JitModuleArtifactRuntimeImport>,
    artifact_runtime_import_gaps: Vec<JitModuleArtifactRuntimeImportGap>,
    symbol_declarations: Vec<JitRuntimeSymbolDeclaration>,
    symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
}

impl JitModuleReadinessPreflight {
    fn new(
        artifact: JitModuleArtifactMetadata,
        artifact_runtime_imports: Vec<JitModuleArtifactRuntimeImport>,
        artifact_runtime_import_gaps: Vec<JitModuleArtifactRuntimeImportGap>,
        symbol_declarations: Vec<JitRuntimeSymbolDeclaration>,
        symbol_gaps: Vec<JitRuntimeSymbolDeclarationGap>,
    ) -> Self {
        Self {
            artifact,
            artifact_runtime_imports,
            artifact_runtime_import_gaps,
            symbol_declarations,
            symbol_gaps,
        }
    }

    /// Returns the artifact metadata that would feed module compilation.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns runtime imports required by this artifact and backed by declarations.
    pub fn artifact_runtime_imports(&self) -> &[JitModuleArtifactRuntimeImport] {
        &self.artifact_runtime_imports
    }

    /// Returns artifact imports that could not be resolved against declarations.
    pub fn artifact_runtime_import_gaps(&self) -> &[JitModuleArtifactRuntimeImportGap] {
        &self.artifact_runtime_import_gaps
    }

    /// Returns CLIF external declarations that are currently shape-known.
    pub fn symbol_declarations(&self) -> &[JitRuntimeSymbolDeclaration] {
        &self.symbol_declarations
    }

    /// Returns stable runtime symbols that still block complete module setup.
    pub fn symbol_gaps(&self) -> &[JitRuntimeSymbolDeclarationGap] {
        &self.symbol_gaps
    }

    /// Returns true when stable symbols and artifact imports are declaration-ready.
    pub fn is_complete(&self) -> bool {
        self.symbol_gaps.is_empty() && self.artifact_runtime_import_gaps.is_empty()
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
    artifact_runtime_imports: Vec<JitModuleArtifactRuntimeImport>,
    symbol_declarations: Vec<JitRuntimeSymbolDeclaration>,
}

impl JitModuleReadinessPlan {
    /// Converts a complete preflight report into a module-readiness plan.
    ///
    /// # Errors
    ///
    /// Returns [`JitModuleReadinessError::UnresolvedArtifactRuntimeImports`]
    /// when the artifact imports an external function that cannot be resolved
    /// against runtime declarations. Returns
    /// [`JitModuleReadinessError::IncompleteRuntimeSymbols`] when runtime-symbol
    /// declaration gaps remain.
    pub fn from_preflight(
        preflight: JitModuleReadinessPreflight,
    ) -> Result<Self, JitModuleReadinessError> {
        if !preflight.artifact_runtime_import_gaps.is_empty() {
            return Err(JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight });
        }

        if !preflight.symbol_gaps.is_empty() {
            return Err(JitModuleReadinessError::IncompleteRuntimeSymbols { preflight });
        }

        Ok(Self {
            artifact: preflight.artifact,
            artifact_runtime_imports: preflight.artifact_runtime_imports,
            symbol_declarations: preflight.symbol_declarations,
        })
    }

    /// Returns the artifact metadata that would feed module compilation.
    pub const fn artifact(&self) -> &JitModuleArtifactMetadata {
        &self.artifact
    }

    /// Returns runtime imports required by this artifact body.
    pub fn artifact_runtime_imports(&self) -> &[JitModuleArtifactRuntimeImport] {
        &self.artifact_runtime_imports
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
    /// Artifact imports could not be resolved against runtime declarations.
    UnresolvedArtifactRuntimeImports {
        /// The preserved readiness report, including imports, declarations, and gaps.
        preflight: JitModuleReadinessPreflight,
    },
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
            Self::UnresolvedArtifactRuntimeImports { preflight } => write!(
                formatter,
                "artifact runtime imports unresolved: {} gap(s) remain before JIT module setup",
                preflight.artifact_runtime_import_gaps().len()
            ),
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
            Self::UnresolvedArtifactRuntimeImports { .. }
            | Self::IncompleteRuntimeSymbols { .. } => None,
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
/// The report carries the artifact metadata, artifact-specific runtime imports,
/// CLIF declarations for callable runtime symbols, and the gaps that still block
/// complete module setup.
///
/// # Errors
///
/// Returns [`JitModuleReadinessError::SymbolDeclaration`] if runtime-symbol
/// declaration metadata cannot be built.
pub fn jit_module_readiness_preflight_for_artifact(
    artifact: &JitClifArtifact,
) -> Result<JitModuleReadinessPreflight, JitModuleReadinessError> {
    let symbol_preflight = jit_runtime_symbol_declaration_preflight()?;
    let (artifact_runtime_imports, artifact_runtime_import_gaps) =
        artifact_runtime_import_preflight(artifact.function(), symbol_preflight.declarations());
    Ok(JitModuleReadinessPreflight::new(
        JitModuleArtifactMetadata::from_artifact(artifact),
        artifact_runtime_imports,
        artifact_runtime_import_gaps,
        symbol_preflight.declarations().to_vec(),
        symbol_preflight.gaps().to_vec(),
    ))
}

/// Builds complete address-free module setup metadata for `artifact`.
///
/// This is a strict gate: it returns a plan only when the artifact's imported
/// runtime functions resolve against declarations and every stable runtime
/// symbol has declaration metadata. In the current implementation helper symbols
/// and value-only builtins intentionally make this return an incomplete error.
///
/// # Errors
///
/// Returns [`JitModuleReadinessError::SymbolDeclaration`] if runtime-symbol
/// declaration metadata cannot be built. Returns
/// [`JitModuleReadinessError::UnresolvedArtifactRuntimeImports`] while artifact
/// imports are unresolved. Returns
/// [`JitModuleReadinessError::IncompleteRuntimeSymbols`] while any stable runtime
/// symbol is missing declaration metadata.
pub fn jit_module_readiness_plan_for_artifact(
    artifact: &JitClifArtifact,
) -> Result<JitModuleReadinessPlan, JitModuleReadinessError> {
    let preflight = jit_module_readiness_preflight_for_artifact(artifact)?;
    JitModuleReadinessPlan::from_preflight(preflight)
}

fn artifact_runtime_import_preflight(
    function: &Function,
    declarations: &[JitRuntimeSymbolDeclaration],
) -> (
    Vec<JitModuleArtifactRuntimeImport>,
    Vec<JitModuleArtifactRuntimeImportGap>,
) {
    let mut imports = Vec::new();
    let mut gaps = Vec::new();

    for (_func_ref, import) in function.dfg.ext_funcs.iter() {
        let Some((symbol_name, user_external_name)) =
            runtime_symbol_for_external_name(function, &import.name)
        else {
            gaps.push(JitModuleArtifactRuntimeImportGap::UnknownExternalName {
                display_name: safe_external_name_display(function, &import.name),
            });
            continue;
        };

        let Some(declaration) = declarations
            .iter()
            .find(|declaration| declaration.symbol_name() == symbol_name)
        else {
            gaps.push(JitModuleArtifactRuntimeImportGap::MissingDeclaration {
                symbol_name: symbol_name.to_owned(),
                user_external_name,
            });
            continue;
        };

        let Some(signature) = function.dfg.signatures.get(import.signature) else {
            gaps.push(JitModuleArtifactRuntimeImportGap::MissingImportSignature {
                symbol_name: symbol_name.to_owned(),
                user_external_name,
            });
            continue;
        };

        if signature != declaration.signature() {
            gaps.push(JitModuleArtifactRuntimeImportGap::SignatureMismatch {
                symbol_name: symbol_name.to_owned(),
                user_external_name,
            });
            continue;
        }

        imports.push(JitModuleArtifactRuntimeImport::new(
            symbol_name.to_owned(),
            user_external_name,
        ));
    }

    (imports, gaps)
}

fn runtime_symbol_for_external_name(
    function: &Function,
    name: &ExternalName,
) -> Option<(&'static str, UserExternalName)> {
    let ExternalName::User(user_name_ref) = name else {
        return None;
    };
    let user_external_name = function
        .params
        .user_named_funcs()
        .get(*user_name_ref)?
        .clone();

    match (user_external_name.namespace, user_external_name.index) {
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_ENV_GET_FUNCTION_INDEX) => {
            Some((AOS_ENV_GET_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_FORCE_FUNCTION_INDEX) => {
            Some((AOS_FORCE_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_APPLY_FUNCTION_INDEX) => {
            Some((AOS_APPLY_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_HAS_ATTR_FUNCTION_INDEX) => {
            Some((AOS_HAS_ATTR_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_SELECT_IC_FUNCTION_INDEX) => {
            Some((AOS_SELECT_IC_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_UPDATE_FUNCTION_INDEX) => {
            Some((AOS_UPDATE_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_DEOPT_FUNCTION_INDEX) => {
            Some((AOS_DEOPT_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_UPVAL_GET_FUNCTION_INDEX) => {
            Some((AOS_UPVAL_GET_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_PRIMOP_CALL_FUNCTION_INDEX) => {
            Some((AOS_PRIMOP_CALL_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_STRING_LENGTH_FUNCTION_INDEX) => {
            Some((AOS_STRING_LENGTH_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_ALLOC_CONS_FUNCTION_INDEX) => {
            Some((AOS_ALLOC_CONS_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_JIT_STACK_MAP_ENTER_FUNCTION_INDEX) => {
            Some((AOS_JIT_STACK_MAP_ENTER_SYMBOL, user_external_name))
        }
        (AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, AOS_JIT_STACK_MAP_EXIT_FUNCTION_INDEX) => {
            Some((AOS_JIT_STACK_MAP_EXIT_SYMBOL, user_external_name))
        }
        _ => None,
    }
}

fn safe_external_name_display(function: &Function, name: &ExternalName) -> String {
    match name {
        ExternalName::User(user_name_ref) => function
            .params
            .user_named_funcs()
            .get(*user_name_ref)
            .map(|user_external_name| {
                format!(
                    "u{}:{}",
                    user_external_name.namespace, user_external_name.index
                )
            })
            .unwrap_or_else(|| name.display(None).to_string()),
        _ => name.display(None).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use cranelift_codegen::ir::{ExtFuncData, SigRef, UserExternalNameRef};
    use ratchet_core::{
        EffectClass, IrArena, IrData, IrId, IrKind, IrNode, RuntimeSymbolKind,
        runtime_helper_call_signature, runtime_thunk_call_signature, syntax::Span,
    };
    use ratchet_value::value::Value;

    use super::*;
    use crate::{
        abi::clif_signature_for_runtime_call,
        artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource},
        lower::{
            clif_external_name_for_aos_apply, clif_external_name_for_aos_env_get,
            clif_external_name_for_aos_force, clif_external_name_for_aos_jit_stack_map_enter,
            clif_external_name_for_aos_jit_stack_map_exit, clif_name_for_ir_root,
            lower_apply_local_slots_ir_thunk_body_artifact, lower_constant_ir_thunk_body_artifact,
            lower_constant_thunk_body_artifact, lower_env_get_ir_thunk_body_artifact,
            lower_forced_env_get_ir_thunk_body_artifact,
        },
        tier::JitTier,
    };

    mod stack_map_binding;

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
        assert!(preflight.declaration_for_symbol("aos_apply").is_some());
        assert!(preflight.declaration_for_symbol("aos_deopt").is_some());
        assert!(preflight.declaration_for_symbol("aos_env_get").is_some());
        assert!(
            preflight
                .declaration_for_symbol("aos_blackhole_check")
                .is_some()
        );
        assert!(preflight.declaration_for_symbol("aos_force").is_some());
        assert!(preflight.declaration_for_symbol("aos_select_ic").is_some());
        assert!(preflight.declaration_for_symbol("aos_update").is_some());
        assert!(preflight.declaration_for_symbol("aos_throw").is_some());
        assert!(preflight.artifact_runtime_imports().is_empty());
        assert!(preflight.artifact_runtime_import_gaps().is_empty());
        assert!(preflight.gap_for_symbol("aos_blackhole_check").is_none());
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
        assert!(preflight.declaration_for_symbol("aos_force").is_some());
        assert!(
            preflight
                .declaration_for_symbol("aos_blackhole_check")
                .is_some()
        );
    }

    #[test]
    fn module_readiness_plan_preserves_complete_preflight_metadata() {
        let artifact = lower_constant_thunk_body_artifact(Value::bool(true))
            .expect("constant artifact lowers");
        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");
        let complete = JitModuleReadinessPreflight::new(
            JitModuleArtifactMetadata::from_artifact(&artifact),
            preflight.artifact_runtime_imports().to_vec(),
            Vec::new(),
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
        assert!(plan.artifact_runtime_imports().is_empty());
        assert_eq!(
            plan.declaration_for_symbol("nix.builtin.derivationStrict")
                .map(JitRuntimeSymbolDeclaration::kind),
            Some(RuntimeSymbolKind::Builtin)
        );
    }

    #[test]
    fn module_readiness_preflight_records_env_get_artifact_import() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 4 },
            )],
            Vec::new(),
        );
        let artifact = lower_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
            .expect("env-get artifact lowers");
        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");

        assert_eq!(preflight.artifact_runtime_imports().len(), 1);
        assert!(preflight.artifact_runtime_import_gaps().is_empty());

        let artifact_import = &preflight.artifact_runtime_imports()[0];
        assert_eq!(artifact_import.symbol_name(), "aos_env_get");
        assert_eq!(
            artifact_import.user_external_name(),
            &clif_external_name_for_aos_env_get()
        );
        assert!(preflight.declaration_for_symbol("aos_env_get").is_some());
    }

    #[test]
    fn module_readiness_preflight_records_apply_artifact_imports() {
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Local { slot: 2 },
                ),
                IrNode::new(
                    IrKind::LocalVar,
                    Span::new(2, 3),
                    EffectClass::pure(),
                    IrData::Local { slot: 5 },
                ),
                IrNode::new(
                    IrKind::Apply,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(1),
                    },
                ),
            ],
            Vec::new(),
        );
        let artifact = lower_apply_local_slots_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("apply artifact lowers");
        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");
        let imports = preflight
            .artifact_runtime_imports()
            .iter()
            .map(|artifact_import| {
                (
                    artifact_import.symbol_name(),
                    artifact_import.user_external_name().clone(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            imports,
            vec![
                ("aos_env_get", clif_external_name_for_aos_env_get()),
                ("aos_apply", clif_external_name_for_aos_apply()),
            ]
        );
        assert!(preflight.artifact_runtime_import_gaps().is_empty());
        assert!(preflight.declaration_for_symbol("aos_env_get").is_some());
        assert!(preflight.declaration_for_symbol("aos_apply").is_some());
    }

    #[test]
    fn module_readiness_plan_preserves_artifact_runtime_imports_when_complete() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 8 },
            )],
            Vec::new(),
        );
        let artifact = lower_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
            .expect("env-get artifact lowers");
        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");
        let complete = JitModuleReadinessPreflight::new(
            JitModuleArtifactMetadata::from_artifact(&artifact),
            preflight.artifact_runtime_imports().to_vec(),
            Vec::new(),
            preflight.symbol_declarations().to_vec(),
            Vec::new(),
        );

        let plan = JitModuleReadinessPlan::from_preflight(complete)
            .expect("synthetic complete env-get preflight becomes a plan");

        assert_eq!(plan.artifact_runtime_imports().len(), 1);
        assert_eq!(
            plan.artifact_runtime_imports()[0].symbol_name(),
            "aos_env_get"
        );
    }

    #[test]
    fn module_readiness_preflight_reports_unknown_artifact_imports() {
        let artifact = artifact_with_runtime_helper_import(UserExternalName::new(
            AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
            99,
        ));

        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");

        assert!(preflight.artifact_runtime_imports().is_empty());
        assert_eq!(
            preflight.artifact_runtime_import_gaps(),
            &[JitModuleArtifactRuntimeImportGap::UnknownExternalName {
                display_name: "u8:99".to_owned(),
            }]
        );
        assert!(!preflight.is_complete());
    }

    #[test]
    fn module_readiness_preflight_reports_dangling_user_external_names_without_panic() {
        let mut function = Function::with_name_signature(
            UserFuncName::default(),
            clif_signature_for_runtime_call(runtime_thunk_call_signature())
                .expect("thunk signature lowers"),
        );
        let env_get_signature = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_env_get")
                .expect("env-get helper signature is core-owned"),
        )
        .expect("env-get signature lowers");
        let signature_ref = function.import_signature(env_get_signature);
        function.import_function(ExtFuncData {
            name: ExternalName::user(UserExternalNameRef::from_u32(99)),
            signature: signature_ref,
            colocated: false,
        });
        let artifact = JitClifArtifact::new(
            JitTier::Tier1Baseline,
            JitClifArtifactKind::ThunkBody,
            JitClifArtifactSource::ConstantSmoke,
            function,
        );

        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");

        assert!(preflight.artifact_runtime_imports().is_empty());
        assert_eq!(
            preflight.artifact_runtime_import_gaps(),
            &[JitModuleArtifactRuntimeImportGap::UnknownExternalName {
                display_name: "userextname99".to_owned(),
            }]
        );
        assert!(!preflight.is_complete());
    }

    #[test]
    fn module_readiness_preflight_reports_missing_artifact_import_declarations() {
        let artifact = artifact_with_runtime_helper_import(clif_external_name_for_aos_env_get());

        let (imports, gaps) = artifact_runtime_import_preflight(artifact.function(), &[]);

        assert!(imports.is_empty());
        assert_eq!(
            gaps,
            [JitModuleArtifactRuntimeImportGap::MissingDeclaration {
                symbol_name: "aos_env_get".to_owned(),
                user_external_name: clif_external_name_for_aos_env_get(),
            }]
        );
    }

    #[test]
    fn module_readiness_preflight_reports_missing_artifact_import_signatures() {
        let mut function = Function::with_name_signature(
            UserFuncName::default(),
            clif_signature_for_runtime_call(runtime_thunk_call_signature())
                .expect("thunk signature lowers"),
        );
        let user_name =
            function.declare_imported_user_function(clif_external_name_for_aos_env_get());
        function.import_function(ExtFuncData {
            name: ExternalName::user(user_name),
            signature: SigRef::from_u32(99),
            colocated: false,
        });
        let artifact = JitClifArtifact::new(
            JitTier::Tier1Baseline,
            JitClifArtifactKind::ThunkBody,
            JitClifArtifactSource::ConstantSmoke,
            function,
        );

        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");

        assert!(preflight.artifact_runtime_imports().is_empty());
        assert_eq!(
            preflight.artifact_runtime_import_gaps(),
            &[JitModuleArtifactRuntimeImportGap::MissingImportSignature {
                symbol_name: "aos_env_get".to_owned(),
                user_external_name: clif_external_name_for_aos_env_get(),
            }]
        );
        assert!(!preflight.is_complete());
    }

    #[test]
    fn module_readiness_preflight_reports_artifact_import_signature_mismatch() {
        let mut function = Function::with_name_signature(
            UserFuncName::default(),
            clif_signature_for_runtime_call(runtime_thunk_call_signature())
                .expect("thunk signature lowers"),
        );
        let mismatched_signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())
            .expect("thunk signature lowers");
        let signature_ref = function.import_signature(mismatched_signature);
        let user_name =
            function.declare_imported_user_function(clif_external_name_for_aos_env_get());
        function.import_function(ExtFuncData {
            name: ExternalName::user(user_name),
            signature: signature_ref,
            colocated: false,
        });
        let artifact = JitClifArtifact::new(
            JitTier::Tier1Baseline,
            JitClifArtifactKind::ThunkBody,
            JitClifArtifactSource::ConstantSmoke,
            function,
        );

        let preflight = jit_module_readiness_preflight_for_artifact(&artifact)
            .expect("module preflight builds");

        assert!(preflight.artifact_runtime_imports().is_empty());
        assert_eq!(
            preflight.artifact_runtime_import_gaps(),
            &[JitModuleArtifactRuntimeImportGap::SignatureMismatch {
                symbol_name: "aos_env_get".to_owned(),
                user_external_name: clif_external_name_for_aos_env_get(),
            }]
        );
        assert!(!preflight.is_complete());
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

    fn artifact_with_runtime_helper_import(
        user_external_name: UserExternalName,
    ) -> JitClifArtifact {
        let mut function = Function::with_name_signature(
            UserFuncName::default(),
            clif_signature_for_runtime_call(runtime_thunk_call_signature())
                .expect("thunk signature lowers"),
        );
        let env_get_signature = clif_signature_for_runtime_call(
            runtime_helper_call_signature("aos_env_get")
                .expect("env-get helper signature is core-owned"),
        )
        .expect("env-get signature lowers");
        let signature_ref = function.import_signature(env_get_signature);
        let user_name = function.declare_imported_user_function(user_external_name);
        function.import_function(ExtFuncData {
            name: ExternalName::user(user_name),
            signature: signature_ref,
            colocated: false,
        });

        JitClifArtifact::new(
            JitTier::Tier1Baseline,
            JitClifArtifactKind::ThunkBody,
            JitClifArtifactSource::ConstantSmoke,
            function,
        )
    }
}
