//! Safe tree-walk evaluator over lowered IR.
//!
//! The tree-walk evaluator is the permanent Phase-1 correctness oracle. These
//! first slices evaluate scalar and list literals, boolean control flow,
//! assertions, boolean operators, string/URI literals and concatenation, list-spine
//! concatenation, static and recursive static attribute-set literals, dynamic
//! string-valued attribute names, static and dynamic string-valued
//! attribute selection, lexical `let` environments, simple and formal-set lambda
//! application, lazy `with` scope lookup, attrset update, thunk forcing, numeric
//! arithmetic, numeric and string/list comparisons, direct strict primops,
//! and scalar/string/function plus structural
//! list/attrset equality to weak head normal form, establishing the arena access
//! and diagnostic surface used by later slices for full string coercion,
//! first-class primitive operations, and derivation boundaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs, io,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    rc::Rc,
};

use base64::Engine as _;
use md5::{Digest as _, Md5};
use serde_json::{Number as JsonNumber, Value as JsonValue};
use sha1::{Digest as _, Sha1};
use sha2::{Sha256, Sha512};
use thiserror::Error;

use super::env::{EvalEnv, EvalEnvError, EvalFrame, EvalWithEnv, EvalWithScope};
use super::heap::{
    EvalHeap, EvalHeapError, EvalLambda, EvalPrimOp, EvalPrimOpArg, EvalThunk, EvalThunkKind,
};
use super::thunk::{ForceClaim, ForceError, ThunkState};
use crate::attrs::{AttrEntry, AttrError, FlatAttrs};
use crate::compile::{
    FrameId, Ir, IrAttrPathId, IrAttrPathSegment, IrBindingSlice, IrChildSlice, IrData, IrId,
    IrKind, IrNode, IrShapeId,
};
use crate::list::{NixList, NixListError};
use crate::runtime::builtins::*;
use crate::string::{ContextElement, ContextKind, NixString, NixStringError, StringContext};
use crate::syntax::{BinOpKind, Span, Symbol, SymbolTable, UnaryOpKind};
use crate::value::{Value, ValueTag};

const TO_STRING_ATTR: &[u8] = b"__toString";
const OUT_PATH_ATTR: &[u8] = b"outPath";
const NAME_ATTR: &[u8] = b"name";
const VALUE_ATTR: &[u8] = b"value";
const HASH_ATTR: &[u8] = b"hash";
const HASH_ALGO_ATTR: &[u8] = b"hashAlgo";
const TO_HASH_FORMAT_ATTR: &[u8] = b"toHashFormat";
const DEFAULT_STORE_DIR: &[u8] = b"/nix/store";
const I64_MAX_EXCLUSIVE_AS_F64: f64 = 9_223_372_036_854_775_808.0;
const NIX_BASE32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Evaluates an IR root to weak head normal form with the tree-walk oracle.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if the root node is missing, malformed for its IR
/// kind, fails a scalar type check, or belongs to a part of the interpreter that
/// this Phase-1 slice has not implemented yet. Returns
/// [`TreeWalkErrorKind::HeapValueRequiresOwner`] if the root evaluates to a
/// heap-backed value; use [`eval_whnf_owned`] for those values so their
/// evaluator heap stays alive.
pub fn eval_whnf(ir: &Ir) -> Result<Value, TreeWalkError> {
    eval_whnf_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root to weak head normal form with explicit evaluator options.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if the root node is missing, malformed for its IR
/// kind, fails a scalar type check, or belongs to a part of the interpreter that
/// this Phase-1 slice has not implemented yet. Returns
/// [`TreeWalkErrorKind::HeapValueRequiresOwner`] if the root evaluates to a
/// heap-backed value; use [`eval_whnf_owned_with_options`] for those values so
/// their evaluator heap stays alive.
pub fn eval_whnf_with_options(ir: &Ir, options: TreeWalkOptions) -> Result<Value, TreeWalkError> {
    let outcome = eval_whnf_owned_with_options(ir, options)?;
    if outcome.value.tag().is_heap() {
        let span = ir
            .arena
            .node(ir.root)
            .map(|node| node.span)
            .unwrap_or_default();
        return Err(TreeWalkError::new(
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: outcome.value.tag(),
            },
            span,
        ));
    }
    Ok(outcome.value)
}

/// Evaluates an IR root while returning the heap that owns heap-backed values.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned(ir: &Ir) -> Result<EvalOutcome, TreeWalkError> {
    eval_whnf_owned_with_options(ir, TreeWalkOptions::default())
}

/// Evaluates an IR root with explicit options while returning the owning heap.
///
/// # Errors
///
/// Returns [`TreeWalkError`] if root evaluation fails.
pub fn eval_whnf_owned_with_options(
    ir: &Ir,
    options: TreeWalkOptions,
) -> Result<EvalOutcome, TreeWalkError> {
    let mut evaluator = TreeWalk::with_options(ir, options);
    let value = evaluator.eval_root()?;
    Ok(EvalOutcome {
        value,
        heap: evaluator.heap,
    })
}

/// A tree-walk evaluation result with its owning evaluator heap.
#[derive(Debug)]
pub struct EvalOutcome {
    value: Value,
    heap: EvalHeap,
}

impl EvalOutcome {
    /// Returns the evaluated root value.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns the heap that owns heap-backed values in this result.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Consumes the outcome into its value and heap.
    pub fn into_parts(self) -> (Value, EvalHeap) {
        (self.value, self.heap)
    }
}

/// Runtime options used by the tree-walk evaluator.
///
/// These options carry interpreter settings that C++ Nix normally reads from
/// its process configuration, while keeping the Phase-1 oracle deterministic
/// and independent from ambient host state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkOptions {
    store_dir: Vec<u8>,
    current_system: Option<Vec<u8>>,
    current_time: Option<i64>,
    env_vars: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Default for TreeWalkOptions {
    fn default() -> Self {
        Self {
            store_dir: DEFAULT_STORE_DIR.to_vec(),
            current_system: None,
            current_time: None,
            env_vars: BTreeMap::new(),
        }
    }
}

impl TreeWalkOptions {
    /// Creates evaluator options using Nix-compatible defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates evaluator options with a configured Nix store directory.
    ///
    /// Empty store directories fall back to `/nix/store`. Absolute store
    /// directories are normalized by removing repeated separators, trailing
    /// separators, `.` path components, and reducible `..` path components
    /// before they become visible through `builtins.storeDir`.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `store_dir` is relative.
    pub fn with_store_dir(store_dir: impl Into<Vec<u8>>) -> Result<Self, TreeWalkOptionsError> {
        Ok(Self {
            store_dir: normalize_store_dir(store_dir.into())?,
            ..Self::default()
        })
    }

    /// Creates evaluator options with one configured environment variable.
    ///
    /// Only variables inserted into these options are visible to
    /// `builtins.getEnv`; the evaluator never reads the ambient process
    /// environment.
    pub fn with_env_var(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        let mut options = Self::default();
        options.set_env_var(name, value);
        options
    }

    /// Creates evaluator options with a configured target system.
    ///
    /// The target system is exposed through `builtins.currentSystem`. Leaving
    /// it unset keeps that builtin unavailable, which lets callers model
    /// pure-eval mode and avoids accidental host introspection.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `current_system` is empty.
    pub fn with_current_system(
        current_system: impl Into<Vec<u8>>,
    ) -> Result<Self, TreeWalkOptionsError> {
        let mut options = Self::default();
        options.set_current_system(current_system)?;
        Ok(options)
    }

    /// Creates evaluator options with a configured evaluation start time.
    ///
    /// The timestamp is exposed through `builtins.currentTime`. Leaving it unset
    /// keeps that builtin unavailable, which lets callers model pure-eval mode
    /// and avoids accidental host clock reads.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `current_time` is negative.
    pub fn with_current_time(current_time: i64) -> Result<Self, TreeWalkOptionsError> {
        let mut options = Self::default();
        options.set_current_time(current_time)?;
        Ok(options)
    }

    /// Replaces the configured Nix store directory.
    ///
    /// Empty store directories fall back to `/nix/store`. Absolute store
    /// directories are normalized by removing repeated separators, trailing
    /// separators, `.` path components, and reducible `..` path components
    /// before they become visible through `builtins.storeDir`.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `store_dir` is relative.
    pub fn set_store_dir(
        &mut self,
        store_dir: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        self.store_dir = normalize_store_dir(store_dir.into())?;
        Ok(())
    }

    /// Replaces the configured target system.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `current_system` is empty.
    pub fn set_current_system(
        &mut self,
        current_system: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        let current_system = current_system.into();
        if current_system.is_empty() {
            return Err(TreeWalkOptionsError::EmptyCurrentSystem);
        }
        self.current_system = Some(current_system);
        Ok(())
    }

    /// Clears the configured target system.
    pub fn clear_current_system(&mut self) {
        self.current_system = None;
    }

    /// Replaces the configured evaluation start time.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `current_time` is negative.
    pub fn set_current_time(&mut self, current_time: i64) -> Result<(), TreeWalkOptionsError> {
        if current_time < 0 {
            return Err(TreeWalkOptionsError::NegativeCurrentTime);
        }
        self.current_time = Some(current_time);
        Ok(())
    }

    /// Clears the configured evaluation start time.
    pub fn clear_current_time(&mut self) {
        self.current_time = None;
    }

    /// Replaces a configured environment variable.
    ///
    /// Only variables inserted into these options are visible to
    /// `builtins.getEnv`; absent variables evaluate to an empty string.
    pub fn set_env_var(&mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.env_vars.insert(name.into(), value.into());
    }

    /// Clears a configured environment variable.
    pub fn clear_env_var(&mut self, name: &[u8]) {
        self.env_vars.remove(name);
    }

    /// Returns the configured Nix store directory.
    pub fn store_dir(&self) -> &[u8] {
        &self.store_dir
    }

    /// Returns the configured target system, if one is available.
    pub fn current_system(&self) -> Option<&[u8]> {
        self.current_system.as_deref()
    }

    /// Returns the configured evaluation start time, if one is available.
    pub const fn current_time(&self) -> Option<i64> {
        self.current_time
    }

    /// Returns the configured value for an environment variable.
    pub fn env_var(&self, name: &[u8]) -> Option<&[u8]> {
        self.env_vars.get(name).map(Vec::as_slice)
    }
}

/// Errors raised while configuring a tree-walk evaluator.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TreeWalkOptionsError {
    /// The configured Nix store directory is not an absolute path.
    #[error("Nix store directory must be absolute")]
    RelativeStoreDir,

    /// The configured target system is empty.
    #[error("Nix currentSystem value must not be empty")]
    EmptyCurrentSystem,

    /// The configured evaluation start time is negative.
    #[error("Nix currentTime value must not be negative")]
    NegativeCurrentTime,
}

fn normalize_store_dir(store_dir: Vec<u8>) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if store_dir.is_empty() {
        return Ok(DEFAULT_STORE_DIR.to_vec());
    }
    if !store_dir.starts_with(b"/") {
        return Err(TreeWalkOptionsError::RelativeStoreDir);
    }

    let mut components = Vec::new();
    for component in store_dir.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            components.pop();
            continue;
        }
        components.push(component);
    }

    let mut normalized = Vec::with_capacity(store_dir.len());
    for component in components {
        normalized.push(b'/');
        normalized.extend_from_slice(component);
    }

    if normalized.is_empty() {
        normalized.push(b'/');
    }

    Ok(normalized)
}

fn file_type_name(file_type: fs::FileType) -> &'static [u8] {
    if file_type.is_file() {
        b"regular"
    } else if file_type.is_dir() {
        b"directory"
    } else if file_type.is_symlink() {
        b"symlink"
    } else {
        b"unknown"
    }
}

fn path_without_trailing_path_markers(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    loop {
        let previous_end = end;
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        if end > 2 && path[end - 2] == b'/' && path[end - 1] == b'.' {
            end -= 2;
            continue;
        }
        if end == 2 && path[0] == b'/' && path[1] == b'.' {
            end = 1;
        }
        if end == previous_end {
            break;
        }
    }
    &path[..end]
}

/// A safe recursive evaluator for lowered IR.
#[derive(Debug)]
pub struct TreeWalk<'ir> {
    ir: &'ir Ir,
    symbols: SymbolTable,
    heap: EvalHeap,
    env: Vec<Rc<EvalFrame>>,
    with_scopes: Vec<EvalWithScope>,
    options: TreeWalkOptions,
    // Lazy identity primops expose their returned argument thunk to strict consumers.
    lazy_identity_thunks: BTreeSet<u64>,
}

impl<'ir> TreeWalk<'ir> {
    /// Creates a tree-walk evaluator over `ir`.
    pub fn new(ir: &'ir Ir) -> Self {
        Self::with_options(ir, TreeWalkOptions::default())
    }

    /// Creates a tree-walk evaluator over `ir` with explicit runtime options.
    pub fn with_options(ir: &'ir Ir, options: TreeWalkOptions) -> Self {
        Self {
            ir,
            symbols: ir.symbols.clone(),
            heap: EvalHeap::new(),
            env: Vec::new(),
            with_scopes: Vec::new(),
            options,
            lazy_identity_thunks: BTreeSet::new(),
        }
    }

    /// Returns the evaluator heap that owns heap-backed values.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Evaluates the IR root to weak head normal form.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if evaluation of the root node fails.
    pub fn eval_root(&mut self) -> Result<Value, TreeWalkError> {
        self.eval_node(self.ir.root)
    }

    /// Evaluates a node to weak head normal form.
    ///
    /// This initial public node entry point is intentionally limited to scalar
    /// literal, list literal, static attrset literal, string and URI literal,
    /// control-flow, boolean operator, string/list concatenation, attrset
    /// update, static
    /// attribute selection, lexical `let` environment, simple and formal-set
    /// lambda application, lazy `with` lookup, numeric arithmetic, numeric and
    /// string/list comparison, direct strict unary primops,
    /// scalar/string/function/list/attrset equality, and conservative thunk
    /// allocation nodes. Remaining environment-dependent nodes return
    /// [`TreeWalkErrorKind::UnsupportedNode`] until later slices add their
    /// explicit runtime context.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if `id` does not address a node in this IR, if
    /// the node payload does not match its kind, if a scalar type check fails,
    /// if thunk forcing fails, or if the node kind is not yet implemented by
    /// this evaluator slice.
    pub fn eval_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        let value = match node.kind {
            IrKind::Int => {
                let IrData::Int(value) = node.data else {
                    return Err(self.invalid_payload(id, &node, "integer payload"));
                };
                Ok(Value::int(value))
            }
            IrKind::Float => {
                let IrData::Float(value) = node.data else {
                    return Err(self.invalid_payload(id, &node, "float payload"));
                };
                Ok(Value::float(value))
            }
            IrKind::Bool => {
                let IrData::Bool(value) = node.data else {
                    return Err(self.invalid_payload(id, &node, "boolean payload"));
                };
                Ok(Value::bool(value))
            }
            IrKind::Null => {
                if node.data != IrData::None {
                    return Err(self.invalid_payload(id, &node, "empty payload"));
                }
                Ok(Value::null())
            }
            IrKind::Str | IrKind::Uri => self.eval_string(id, &node),
            IrKind::Path => self.eval_path(id, &node),
            IrKind::Interp => self.eval_interp(id, &node),
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::WithVar => self.eval_with_var(id, &node),
            IrKind::List => self.eval_list(id, &node),
            IrKind::AttrSet => self.eval_attrset(id, &node),
            IrKind::Lambda => self.eval_lambda(id, &node),
            IrKind::Apply => self.eval_apply(id, &node),
            IrKind::PrimOp => self.eval_primop(id, &node),
            IrKind::Let => self.eval_let(id, &node),
            IrKind::With => self.eval_with(id, &node),
            IrKind::If => self.eval_if(id, &node),
            IrKind::Assert => self.eval_assert(id, &node),
            IrKind::UnaryOp => self.eval_unary(id, &node),
            IrKind::BinOp => self.eval_binary(id, &node),
            IrKind::Select => self.eval_select(id, &node),
            IrKind::HasAttr => self.eval_has_attr(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedNode { id, kind },
                node.span,
            )),
        }?;
        self.force_node_result(id, node.span, value)
    }

    fn force_node_result(
        &mut self,
        id: IrId,
        span: Span,
        mut value: Value,
    ) -> Result<Value, TreeWalkError> {
        loop {
            if self.is_suspended_lazy_identity_thunk(id, span, value)? {
                return Ok(value);
            }
            if !value.is_thunk() {
                return Ok(value);
            }
            let forced = self.force_value(id, span, value)?;
            if forced.raw_eq(value) {
                return Ok(forced);
            }
            value = forced;
        }
    }

    fn is_suspended_lazy_identity_thunk(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if !value.is_thunk() || !self.lazy_identity_thunks.contains(&value.payload_bits()) {
            return Ok(false);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let state = thunk
            .cell()
            .state()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        Ok(state == ThunkState::Suspended)
    }

    fn mark_lazy_identity_thunk(&mut self, value: Value) {
        if value.is_thunk() {
            self.lazy_identity_thunks.insert(value.payload_bits());
        }
    }

    fn eval_lazy_identity_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.is_path_literal_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        self.mark_lazy_identity_thunk(value);
        Ok(value)
    }

    fn is_path_literal_thunk(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if !value.is_thunk() {
            return Ok(false);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let Some(body) = thunk.body() else {
            return Ok(false);
        };
        Ok(self.node(body)?.kind == IrKind::Path)
    }

    fn consume_suspended_lazy_identity_thunk(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if self.is_suspended_lazy_identity_thunk(id, span, value)? {
            self.lazy_identity_thunks.remove(&value.payload_bits());
            return Ok(true);
        }
        Ok(false)
    }

    fn force_demanded_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.consume_suspended_lazy_identity_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        let value = self.force_value(id, span, value)?;
        if self.consume_suspended_lazy_identity_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        Ok(value)
    }

    fn node(&self, id: IrId) -> Result<&IrNode, TreeWalkError> {
        self.ir.arena.node(id).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidNodeId { id }, Span::default())
        })
    }

    fn binding_range(
        &self,
        id: IrId,
        slice: IrBindingSlice,
        span: Span,
    ) -> Result<std::ops::Range<usize>, TreeWalkError> {
        let start = slice.start as usize;
        let end = start.checked_add(slice.len()).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidBindingSlice { id, slice }, span)
        })?;
        if self.ir.bindings.get(start..end).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidBindingSlice { id, slice },
                span,
            ));
        }
        Ok(start..end)
    }

    fn frame_info(
        &self,
        id: IrId,
        frame: FrameId,
        span: Span,
    ) -> Result<&crate::compile::FrameInfo, TreeWalkError> {
        self.ir.frames.get(frame.index()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidFrameId {
                    id,
                    frame: frame.as_u32(),
                },
                span,
            )
        })
    }

    fn capture_env(&self, id: IrId, span: Span) -> Result<EvalEnv, TreeWalkError> {
        EvalEnv::capture(&self.env)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    fn capture_with_env(&self, id: IrId, span: Span) -> Result<EvalWithEnv, TreeWalkError> {
        EvalWithEnv::capture(&self.with_scopes)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    fn clone_env_frames(
        &self,
        id: IrId,
        env: &EvalEnv,
        span: Span,
    ) -> Result<Vec<Rc<EvalFrame>>, TreeWalkError> {
        let frames = env.frames();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(frames.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::CaptureAllocationFailed {
                        frames: frames.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(frames);
        Ok(cloned)
    }

    fn clone_with_scopes(
        &self,
        id: IrId,
        env: &EvalWithEnv,
        span: Span,
    ) -> Result<Vec<EvalWithScope>, TreeWalkError> {
        let scopes = env.scopes();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(scopes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::WithCaptureAllocationFailed {
                        scopes: scopes.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(scopes);
        Ok(cloned)
    }

    fn validate_attrset_shape(
        &self,
        id: IrId,
        shape: IrShapeId,
        shape_keys: &[Symbol],
        binding_range: std::ops::Range<usize>,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let mut binding_keys = 0usize;
        for binding_index in binding_range {
            let binding = self.ir.bindings[binding_index];
            let actual = match binding.key {
                IrAttrPathSegment::Static(symbol) => symbol,
                IrAttrPathSegment::Dynamic(_) => continue,
            };
            let Some(expected) = shape_keys.get(binding_keys).copied() else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetShapeLengthMismatch {
                        id,
                        shape,
                        shape_keys: shape_keys.len(),
                        binding_keys: binding_keys + 1,
                    },
                    span,
                ));
            };
            if expected != actual {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetShapeKeyMismatch {
                        id,
                        shape,
                        index: binding_keys,
                        expected,
                        actual,
                    },
                    span,
                ));
            }
            binding_keys += 1;
        }

        if binding_keys != shape_keys.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::AttrSetShapeLengthMismatch {
                    id,
                    shape,
                    shape_keys: shape_keys.len(),
                    binding_keys,
                },
                span,
            ));
        }

        Ok(())
    }

    fn attr_path(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<&[IrAttrPathSegment], TreeWalkError> {
        self.ir
            .attr_paths
            .get(path.index())
            .map(|segments| segments.as_ref())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidAttrPath { id, path }, span)
            })
    }

    fn attr_path_len(
        &self,
        id: IrId,
        path: IrAttrPathId,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.attr_path(id, path, span)
            .map(|segments| segments.len())
    }

    fn attr_path_segment(
        &self,
        id: IrId,
        path: IrAttrPathId,
        index: usize,
        span: Span,
    ) -> Result<IrAttrPathSegment, TreeWalkError> {
        self.attr_path(id, path, span)?
            .get(index)
            .copied()
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidAttrPath { id, path }, span)
            })
    }

    fn with_chain_scope_count(
        &self,
        id: IrId,
        chain: u32,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        self.ir
            .with_chains
            .get(chain as usize)
            .map(|chain| chain.scopes.len())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidWithChain { id, chain }, span)
            })
    }

    fn with_chain_scope(
        &self,
        id: IrId,
        chain: u32,
        index: usize,
        span: Span,
    ) -> Result<IrId, TreeWalkError> {
        self.ir
            .with_chains
            .get(chain as usize)
            .and_then(|chain| chain.scopes.get(index).copied())
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::InvalidWithChain { id, chain }, span)
            })
    }

    fn with_scope_value(&self, id: IrId, scope: IrId, span: Span) -> Result<Value, TreeWalkError> {
        self.with_scopes
            .iter()
            .rev()
            .find(|active| active.scope() == scope)
            .map(EvalWithScope::value)
            .ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::MissingWithScope { id, scope }, span)
            })
    }

    fn eval_global_fallback(
        &self,
        id: IrId,
        symbol: Symbol,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        match self.symbols.resolve(symbol) {
            Some(b"true") => Ok(Value::bool(true)),
            Some(b"false") => Ok(Value::bool(false)),
            Some(b"null") => Ok(Value::null()),
            Some(_) => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnresolvedWithVar { id, symbol },
                span,
            )),
            None => Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                span,
            )),
        }
    }

    fn invalid_payload(&self, id: IrId, node: &IrNode, expected: &'static str) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::InvalidPayload {
                id,
                kind: node.kind,
                expected,
            },
            node.span,
        )
    }

    fn clone_attr_entries(
        id: IrId,
        span: Span,
        attrs: &FlatAttrs,
    ) -> Result<Vec<AttrEntry>, TreeWalkError> {
        let entries = attrs.entries_by_symbol();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(entries.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: entries.len(),
                    },
                },
                span,
            )
        })?;
        cloned.extend_from_slice(entries);
        Ok(cloned)
    }

    fn clone_list_elements(
        id: IrId,
        span: Span,
        list: &NixList,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let elements = list.as_slice();
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        cloned.extend_from_slice(elements);
        Ok(cloned)
    }

    fn eval_if(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Triple {
            first,
            second,
            third,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "if payload"));
        };
        let selected = if self.eval_bool_node(first)? {
            second
        } else {
            third
        };
        self.eval_node(selected)
    }

    fn eval_assert(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair { first, second } = node.data else {
            return Err(self.invalid_payload(id, node, "assert payload"));
        };
        if self.eval_bool_node(first)? {
            self.eval_node(second)
        } else {
            Err(TreeWalkError::new(
                TreeWalkErrorKind::AssertionFailed { id },
                node.span,
            ))
        }
    }

    fn eval_unary(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Unary { op, operand } = node.data else {
            return Err(self.invalid_payload(id, node, "unary payload"));
        };
        match op {
            UnaryOpKind::Not => Ok(Value::bool(!self.eval_bool_node(operand)?)),
            UnaryOpKind::Neg => self.eval_numeric_negation(id, node, operand),
        }
    }

    fn eval_binary(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Binary { op, lhs, rhs } = node.data else {
            return Err(self.invalid_payload(id, node, "binary payload"));
        };
        match op {
            BinOpKind::And => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                } else {
                    Ok(Value::bool(false))
                }
            }
            BinOpKind::Or => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(true))
                } else {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                }
            }
            BinOpKind::Impl => {
                if self.eval_bool_node(lhs)? {
                    Ok(Value::bool(self.eval_bool_node(rhs)?))
                } else {
                    Ok(Value::bool(true))
                }
            }
            BinOpKind::Add => self.eval_add(id, node, lhs, rhs),
            BinOpKind::Sub => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Sub, lhs, rhs),
            BinOpKind::Mul => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Mul, lhs, rhs),
            BinOpKind::Div => self.eval_numeric_binary(id, node, BinaryArithmeticOp::Div, lhs, rhs),
            BinOpKind::Lt => self.eval_comparison(id, node, ComparisonOp::Lt, lhs, rhs),
            BinOpKind::Gt => self.eval_comparison(id, node, ComparisonOp::Gt, lhs, rhs),
            BinOpKind::Le => self.eval_comparison(id, node, ComparisonOp::Le, lhs, rhs),
            BinOpKind::Ge => self.eval_comparison(id, node, ComparisonOp::Ge, lhs, rhs),
            BinOpKind::Eq => self.eval_equality(id, node, lhs, rhs, false),
            BinOpKind::Ne => self.eval_equality(id, node, lhs, rhs, true),
            BinOpKind::Concat => self.eval_list_concat(id, node, lhs, rhs),
            BinOpKind::Update => self.eval_attr_update(id, node, lhs, rhs),
            BinOpKind::PipeRight | BinOpKind::PipeLeft => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedBinaryOp { id, op },
                node.span,
            )),
        }
    }

    fn eval_string(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "string symbol payload"));
        };
        let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
        })?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                node.span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.heap
            .alloc_string(NixString::from_bytes(owned))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_path(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Symbol(symbol) = node.data else {
            return Err(self.invalid_payload(id, node, "path symbol payload"));
        };
        let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
        })?;
        let path = Self::absolute_path_bytes_for_node(id, node.span, bytes)?;
        self.heap
            .alloc_path(NixString::from_bytes(path))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_interp(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        match node.data {
            IrData::Node(child) => {
                let span = self.node(child)?.span;
                let value = self.eval_node(child)?;
                self.coerce_to_string(child, value, span)
            }
            IrData::Children(children) => {
                let children = self.ir.arena.child_slice(children).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidChildSlice {
                            id,
                            slice: children,
                        },
                        node.span,
                    )
                })?;
                let Some((first, rest)) = children.split_first() else {
                    return self
                        .heap
                        .alloc_string(NixString::default())
                        .map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                        });
                };
                let first_span = self.node(*first)?.span;
                let mut current = {
                    let value = self.eval_node(*first)?;
                    self.coerce_to_string(*first, value, first_span)?
                };
                for child in rest {
                    let child_span = self.node(*child)?.span;
                    let next = {
                        let value = self.eval_node(*child)?;
                        self.coerce_to_string(*child, value, child_span)?
                    };
                    current = self.concat_strings(id, node, current, next)?;
                }
                Ok(current)
            }
            IrData::None => self
                .heap
                .alloc_string(NixString::default())
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                }),
            IrData::Symbol(symbol) => {
                let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
                })?;
                let mut owned = Vec::new();
                owned.try_reserve_exact(bytes.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ByteAllocationFailed {
                            id,
                            len: bytes.len(),
                        },
                        node.span,
                    )
                })?;
                owned.extend_from_slice(bytes);
                self.heap
                    .alloc_string(NixString::from_bytes(owned))
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                    })
            }
            _ => Err(self.invalid_payload(id, node, "interpolation payload")),
        }
    }

    fn coerce_to_string(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        match value.tag() {
            ValueTag::String => Ok(value),
            ValueTag::Attrs => self.coerce_attrs_to_string(id, value, span),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual,
                },
                span,
            )),
        }
    }

    fn coerce_attrs_to_string(
        &mut self,
        id: IrId,
        attrs_value: Value,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        if let Some(hook) = self.attr_value_by_name(id, attrs_value, TO_STRING_ATTR, span)? {
            let hook = self.force_value(id, span, hook)?;
            let value = self.apply_lambda_value(id, span, id, hook, span, id, attrs_value)?;
            return self.coerce_to_string(id, value, span);
        }

        if let Some(out_path) = self.attr_value_by_name(id, attrs_value, OUT_PATH_ATTR, span)? {
            let value = self.force_value(id, span, out_path)?;
            return self.coerce_to_string(id, value, span);
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::Type {
                id,
                expected: "string",
                actual: ValueTag::Attrs,
            },
            span,
        ))
    }

    fn attr_value_by_name(
        &mut self,
        id: IrId,
        attrs_value: Value,
        name: &[u8],
        span: Span,
    ) -> Result<Option<Value>, TreeWalkError> {
        let symbol = self.symbols.intern(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                source.span(),
            )
        })?;
        let attrs = self
            .heap
            .get_attrs(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        Ok(attrs.get(symbol))
    }

    fn context_free_string_bytes(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        let string = self
            .heap
            .get_string(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if string.has_context() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::StringContextNotAllowed { id, op },
                span,
            ));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(string.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: string.len(),
                },
                span,
            )
        })?;
        bytes.extend_from_slice(string.bytes());
        Ok(bytes)
    }

    fn coerce_to_path_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let bytes = if value.tag() == ValueTag::Path {
            let path = self.clone_path_value(id, span, value)?;
            Self::copy_bytes_for_node(id, span, path.bytes())?
        } else {
            let string = self.coerce_to_string(id, value, span)?;
            self.context_free_string_bytes(id, span, string, op)?
        };
        if !Path::new(OsStr::from_bytes(&bytes)).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute { id, path: bytes },
                span,
            ));
        }
        Ok(bytes)
    }

    fn eval_attr_name(
        &mut self,
        id: IrId,
        segment: IrAttrPathSegment,
        null_policy: DynamicAttrNullPolicy,
        span: Span,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        match segment {
            IrAttrPathSegment::Static(symbol) => {
                if self.symbols.resolve(symbol).is_none() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol { id, symbol },
                        span,
                    ));
                }
                Ok(Some(symbol))
            }
            IrAttrPathSegment::Dynamic(dynamic) => {
                self.eval_dynamic_attr_name(id, self.dynamic_attr_expression(dynamic)?, null_policy)
            }
        }
    }

    fn dynamic_attr_expression(&self, dynamic: IrId) -> Result<IrId, TreeWalkError> {
        let node = self.node(dynamic)?;
        if node.kind == IrKind::Interp {
            if let IrData::Node(child) = node.data {
                return Ok(child);
            }
        }
        Ok(dynamic)
    }

    fn eval_dynamic_attr_name(
        &mut self,
        id: IrId,
        expression: IrId,
        null_policy: DynamicAttrNullPolicy,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        let span = self.node(expression)?.span;
        let value = self.eval_node(expression)?;
        match value.tag() {
            ValueTag::Null if null_policy == DynamicAttrNullPolicy::SkipNull => Ok(None),
            _ => {
                let string = self.coerce_to_string(expression, value, span)?;
                self.intern_string_value(id, string, span).map(Some)
            }
        }
    }

    fn intern_string_value(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Symbol, TreeWalkError> {
        let bytes = {
            let string = self.heap.get_string(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(string.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: string.len(),
                    },
                    span,
                )
            })?;
            bytes.extend_from_slice(string.bytes());
            bytes
        };
        self.symbols.intern(&bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                source.span(),
            )
        })
    }

    fn eval_list(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Children(children) = node.data else {
            return Err(self.invalid_payload(id, node, "list children"));
        };
        let children = self.ir.arena.child_slice(children).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidChildSlice {
                    id,
                    slice: children,
                },
                node.span,
            )
        })?;
        let mut elements = Vec::new();
        elements.try_reserve_exact(children.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: children.len(),
                },
                node.span,
            )
        })?;
        for child in children.iter().copied() {
            elements.push(self.eval_lazy_node(child)?);
        }
        self.heap
            .alloc_list(NixList::new(elements))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_local_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Local { slot } = node.data else {
            return Err(self.invalid_payload(id, node, "local payload"));
        };
        let Some(frame) = self.env.last() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingEnvironment { id },
                node.span,
            ));
        };
        frame
            .get(slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span))
    }

    fn eval_upval_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Upval { depth, slot } = node.data else {
            return Err(self.invalid_payload(id, node, "upvalue payload"));
        };
        let depth = depth as usize;
        if depth >= self.env.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidUpvalueDepth {
                    id,
                    depth,
                    frames: self.env.len(),
                },
                node.span,
            ));
        }
        let index = self.env.len() - 1 - depth;
        self.env[index]
            .get(slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span))
    }

    fn eval_lazy_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        if node.kind == IrKind::ThunkAlloc {
            return self.eval_thunk_alloc(id, &node);
        }
        self.eval_node(id)
    }

    fn eval_nested_equality_operand(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        match node.kind {
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            _ => self.eval_node(id),
        }
    }

    fn eval_thunk_alloc(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Node(body) = node.data else {
            return Err(self.invalid_payload(id, node, "thunk body"));
        };
        self.alloc_thunk_for_node(id, body, node.span)
    }

    fn alloc_thunk_for_node(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        self.node(body)?;
        let env = self.capture_env(id, span)?;
        let with_env = self.capture_with_env(id, span)?;
        self.heap
            .alloc_thunk(EvalThunk::with_captures(body, env, with_env))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    #[allow(clippy::too_many_arguments)]
    fn alloc_apply_thunk(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        self.heap
            .alloc_thunk(EvalThunk::apply(
                function_id,
                function_span,
                function,
                argument_id,
                argument,
            ))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn force_value(&mut self, id: IrId, span: Span, value: Value) -> Result<Value, TreeWalkError> {
        if !value.is_thunk() {
            return Ok(value);
        }
        let forced_payload = value.payload_bits();
        let thunk = self
            .heap
            .clone_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        match thunk
            .cell()
            .begin_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        {
            ForceClaim::AlreadyForced(value) => {
                self.lazy_identity_thunks.remove(&forced_payload);
                Ok(value)
            }
            ForceClaim::Claimed(guard) => {
                let result = match thunk.kind() {
                    EvalThunkKind::Node {
                        body,
                        env,
                        with_env,
                    } => {
                        let thunk_env = self.clone_env_frames(id, env, span)?;
                        let thunk_with_env = self.clone_with_scopes(id, with_env, span)?;
                        let saved_env = std::mem::replace(&mut self.env, thunk_env);
                        let saved_with_scopes =
                            std::mem::replace(&mut self.with_scopes, thunk_with_env);
                        let result = self.eval_node(*body);
                        self.env = saved_env;
                        self.with_scopes = saved_with_scopes;
                        result
                    }
                    EvalThunkKind::Apply {
                        function_id,
                        function_span,
                        function,
                        argument_id,
                        argument,
                    } => self.apply_lambda_value(
                        id,
                        span,
                        *function_id,
                        *function,
                        *function_span,
                        *argument_id,
                        *argument,
                    ),
                };
                let value = result?;
                let value = guard.finish(value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
                })?;
                self.lazy_identity_thunks.remove(&forced_payload);
                Ok(value)
            }
        }
    }

    fn eval_let(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Let {
            bindings,
            body,
            frame,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "let payload"));
        };
        let Some(frame) = frame else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingFrameMetadata { id },
                node.span,
            ));
        };
        let slot_count = self.frame_info(id, frame, node.span)?.slot_count as usize;
        let binding_range = self.binding_range(id, bindings, node.span)?;
        if binding_range.len() != slot_count {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::LetFrameSlotMismatch {
                    id,
                    frame_slots: slot_count,
                    bindings: binding_range.len(),
                },
                node.span,
            ));
        }
        let frame_values = EvalFrame::new(slot_count).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
        })?;
        self.env.push(Rc::clone(&frame_values));
        let result = (|| {
            for (slot, binding_index) in binding_range.enumerate() {
                let binding = self.ir.bindings[binding_index];
                if !matches!(binding.key, IrAttrPathSegment::Static(_)) {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::UnsupportedLetBindingKey { id },
                        node.span,
                    ));
                }
                let value = self.eval_lazy_node(binding.value)?;
                frame_values.set(slot as u32, value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                })?;
            }
            self.eval_node(body)
        })();
        let _ = self.env.pop();
        result
    }

    fn eval_with(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair {
            first: scope,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "with pair"));
        };
        self.node(body)?;
        let value = self.alloc_thunk_for_node(id, scope, node.span)?;
        self.with_scopes.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::WithScopeAllocationFailed {
                    id,
                    scopes: self.with_scopes.len() + 1,
                },
                node.span,
            )
        })?;
        self.with_scopes.push(EvalWithScope::new(scope, value));
        let result = self.eval_node(body);
        let _ = self.with_scopes.pop();
        result
    }

    fn eval_with_var(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::WithVar { symbol, chain } = node.data else {
            return Err(self.invalid_payload(id, node, "with-var payload"));
        };
        if self.ir.symbols.resolve(symbol).is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol { id, symbol },
                node.span,
            ));
        }

        let scope_count = self.with_chain_scope_count(id, chain, node.span)?;
        for index in 0..scope_count {
            let scope = self.with_chain_scope(id, chain, index, node.span)?;
            let scope_span = self.node(scope)?.span;
            let scope_value = self.with_scope_value(id, scope, node.span)?;
            let attrs_value = self.force_value(scope, scope_span, scope_value)?;
            if attrs_value.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: scope,
                        expected: "attrs",
                        actual: attrs_value.tag(),
                    },
                    scope_span,
                ));
            }
            let selected = {
                let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                })?;
                attrs.get(symbol)
            };
            if let Some(value) = selected {
                return Ok(value);
            }
        }

        self.eval_global_fallback(id, symbol, node.span)
    }

    fn eval_lambda(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Lambda {
            pattern,
            body,
            frame,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "lambda payload"));
        };
        let Some(frame) = frame else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingFrameMetadata { id },
                node.span,
            ));
        };
        self.node(pattern)?;
        self.node(body)?;
        self.frame_info(id, frame, node.span)?;
        let env = self.capture_env(id, node.span)?;
        let with_env = self.capture_with_env(id, node.span)?;
        self.heap
            .alloc_lambda(EvalLambda::with_captures(
                pattern, body, frame, env, with_env,
            ))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_apply(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Pair { first, second } = node.data else {
            return Err(self.invalid_payload(id, node, "application pair"));
        };
        let function_span = self.node(first)?.span;
        let mut function = self.eval_node(first)?;
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop)
            && !self.node_is_break_primop(first)?
        {
            function = self.force_demanded_value(first, function_span, function)?;
        }
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: first,
                    expected: "lambda",
                    actual: function.tag(),
                },
                function_span,
            ));
        }
        let argument = self.eval_lazy_node(second)?;
        self.apply_lambda_value(
            id,
            node.span,
            first,
            function,
            function_span,
            second,
            argument,
        )
    }

    fn node_is_break_primop(&self, id: IrId) -> Result<bool, TreeWalkError> {
        let node = self.node(id)?;
        let IrData::PrimOp { symbol, .. } = node.data else {
            return Ok(false);
        };
        Ok(node.kind == IrKind::PrimOp && self.symbols.resolve(symbol) == Some(b"break"))
    }

    fn eval_primop(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::PrimOp { symbol, args } = node.data else {
            return Err(self.invalid_payload(id, node, "primop payload"));
        };
        let name = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, node.span)
        })?;
        let args = self.ir.arena.child_slice(args).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidChildSlice { id, slice: args },
                node.span,
            )
        })?;
        let Some(builtin) = lookup_builtin_by_name(name) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedPrimOp { id, symbol },
                node.span,
            ));
        };
        apply_builtin_direct(
            self,
            builtin,
            BuiltinCall::new(id, node.span, symbol),
            node,
            args,
        )
    }

    fn eval_strict_unary_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        primop: StrictUnaryPrimOp,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictUnaryPrimOp::IsAttrs => Ok(Value::bool(value.tag() == ValueTag::Attrs)),
            StrictUnaryPrimOp::IsList => Ok(Value::bool(value.tag() == ValueTag::List)),
            StrictUnaryPrimOp::IsFunction => Ok(Value::bool(matches!(
                value.tag(),
                ValueTag::Lambda | ValueTag::Primop
            ))),
            StrictUnaryPrimOp::IsString => Ok(Value::bool(value.tag() == ValueTag::String)),
            StrictUnaryPrimOp::IsInt => Ok(Value::bool(value.tag() == ValueTag::Int)),
            StrictUnaryPrimOp::IsFloat => Ok(Value::bool(value.tag() == ValueTag::Float)),
            StrictUnaryPrimOp::IsBool => Ok(Value::bool(value.tag() == ValueTag::Bool)),
            StrictUnaryPrimOp::IsNull => Ok(Value::bool(value.tag() == ValueTag::Null)),
            StrictUnaryPrimOp::IsPath => Ok(Value::bool(value.tag() == ValueTag::Path)),
            StrictUnaryPrimOp::TypeOf => {
                let Some(name) = value.tag().nix_type_name() else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "weak head normal form",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                };
                self.alloc_static_string(id, span, name.as_bytes())
            }
            StrictUnaryPrimOp::Length => {
                if value.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "list",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let list = self.heap.get_list(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                let len = i64::try_from(list.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListLengthOverflow {
                            id: argument,
                            len: list.len(),
                        },
                        argument_span,
                    )
                })?;
                Ok(Value::int(len))
            }
            StrictUnaryPrimOp::AttrNames => {
                if value.tag() != ValueTag::Attrs {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "attrs",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let names = {
                    let attrs = self.heap.get_attrs(value).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Heap {
                                id: argument,
                                source,
                            },
                            argument_span,
                        )
                    })?;
                    let mut names = Vec::new();
                    names.try_reserve_exact(attrs.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: attrs.len(),
                            },
                            span,
                        )
                    })?;
                    for entry in attrs.iter_lexicographic() {
                        names.push(entry.key);
                    }
                    names
                };
                let mut elements = Vec::new();
                elements.try_reserve_exact(names.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: names.len(),
                        },
                        span,
                    )
                })?;
                for symbol in names {
                    elements.push(self.alloc_symbol_string(id, span, symbol)?);
                }
                self.heap
                    .alloc_list(NixList::new(elements))
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })
            }
            StrictUnaryPrimOp::AttrValues => {
                if value.tag() != ValueTag::Attrs {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "attrs",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let values = {
                    let attrs = self.heap.get_attrs(value).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Heap {
                                id: argument,
                                source,
                            },
                            argument_span,
                        )
                    })?;
                    let mut values = Vec::new();
                    values.try_reserve_exact(attrs.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: attrs.len(),
                            },
                            span,
                        )
                    })?;
                    for entry in attrs.iter_lexicographic() {
                        values.push(entry.value);
                    }
                    values
                };
                self.heap
                    .alloc_list(NixList::new(values))
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })
            }
            StrictUnaryPrimOp::Tail => {
                if value.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "list",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let values = {
                    let list = self.heap.get_list(value).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Heap {
                                id: argument,
                                source,
                            },
                            argument_span,
                        )
                    })?;
                    if list.is_empty() {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::EmptyListPrimOp {
                                id: argument,
                                op: "tail",
                            },
                            argument_span,
                        ));
                    }
                    let tail = &list.as_slice()[1..];
                    let mut values = Vec::new();
                    values.try_reserve_exact(tail.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: tail.len(),
                            },
                            span,
                        )
                    })?;
                    values.extend_from_slice(tail);
                    values
                };
                self.heap
                    .alloc_list(NixList::new(values))
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })
            }
            StrictUnaryPrimOp::Head => {
                if value.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: argument,
                            expected: "list",
                            actual: value.tag(),
                        },
                        argument_span,
                    ));
                }
                let list = self.heap.get_list(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                let Some(head) = list.get(0) else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::EmptyListPrimOp {
                            id: argument,
                            op: "head",
                        },
                        argument_span,
                    ));
                };
                Ok(head)
            }
            StrictUnaryPrimOp::Ceil => self.eval_float_to_int_primop(
                id,
                span,
                argument,
                value,
                f64::ceil,
                ArithmeticOp::Ceil,
            ),
            StrictUnaryPrimOp::Floor => self.eval_float_to_int_primop(
                id,
                span,
                argument,
                value,
                f64::floor,
                ArithmeticOp::Floor,
            ),
            StrictUnaryPrimOp::HasContext => {
                self.eval_has_context_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::GetContext => {
                self.eval_get_context_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::GetEnv => {
                self.eval_get_env_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::AddDrvOutputDependencies => {
                self.eval_add_drv_output_dependencies_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::UnsafeDiscardOutputDependency => {
                self.eval_unsafe_discard_output_dependency_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::UnsafeDiscardStringContext => {
                self.eval_unsafe_discard_string_context_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::StringLength => {
                self.eval_string_length_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::BaseNameOf => {
                self.eval_base_name_of_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::DirOf => self.eval_dir_of_primop(argument, argument_span, value),
            StrictUnaryPrimOp::ParseDrvName => {
                self.eval_parse_drv_name_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::SplitVersion => {
                self.eval_split_version_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::FromJson => {
                self.eval_from_json_primop(argument, argument_span, value)
            }
            StrictUnaryPrimOp::ToString => {
                self.eval_to_string_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ToJson => {
                self.eval_to_json_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ConvertHash => {
                self.eval_convert_hash_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::FunctionArgs => {
                self.eval_function_args_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ListToAttrs => {
                self.eval_list_to_attrs_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::ConcatLists => {
                self.eval_concat_lists_primop(id, span, argument, argument_span, value)
            }
            StrictUnaryPrimOp::Throw => {
                self.eval_throw_abort_primop(ThrowAbortOp::Throw, argument, argument_span, value)
            }
            StrictUnaryPrimOp::Abort => {
                self.eval_throw_abort_primop(ThrowAbortOp::Abort, argument, argument_span, value)
            }
        }
    }

    fn eval_throw_abort_primop(
        &mut self,
        op: ThrowAbortOp,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let message = self.coerce_to_string(argument, value, argument_span)?;
        let message = self.heap.get_string(message).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        let message = Self::copy_bytes_for_node(argument, argument_span, message.bytes())?;

        Err(TreeWalkError::new(
            match op {
                ThrowAbortOp::Throw => TreeWalkErrorKind::Thrown {
                    id: argument,
                    message,
                },
                ThrowAbortOp::Abort => TreeWalkErrorKind::Aborted {
                    id: argument,
                    message,
                },
            },
            argument_span,
        ))
    }

    fn eval_try_eval_direct(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
    ) -> Result<Value, TreeWalkError> {
        match self.eval_node(argument) {
            Ok(value) => self.alloc_try_eval_result(id, span, true, value),
            Err(error) => self.handle_try_eval_error(id, span, error),
        }
    }

    fn eval_try_eval_value(
        &mut self,
        id: IrId,
        span: Span,
        argument: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match self.force_value(argument.id(), argument.span(), argument.value()) {
            Ok(value) => self.alloc_try_eval_result(id, span, true, value),
            Err(error) => self.handle_try_eval_error(id, span, error),
        }
    }

    fn handle_try_eval_error(
        &mut self,
        id: IrId,
        span: Span,
        error: TreeWalkError,
    ) -> Result<Value, TreeWalkError> {
        match error.kind() {
            TreeWalkErrorKind::Thrown { .. } | TreeWalkErrorKind::AssertionFailed { .. } => {
                self.alloc_try_eval_result(id, span, false, Value::bool(false))
            }
            _ => Err(error),
        }
    }

    fn alloc_try_eval_result(
        &mut self,
        id: IrId,
        span: Span,
        success: bool,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let success_key = self.intern_builtin_attr_symbol(id, b"success", span)?;
        let value_key = self.intern_builtin_attr_symbol(id, b"value", span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(2).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len: 2 }, span)
        })?;
        entries.push(AttrEntry::new(success_key, Value::bool(success)));
        entries.push(AttrEntry::new(value_key, value));
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_float_to_int_primop(
        &self,
        id: IrId,
        span: Span,
        argument: IrId,
        value: Value,
        op: fn(f64) -> f64,
        arithmetic_op: ArithmeticOp,
    ) -> Result<Value, TreeWalkError> {
        let argument_span = self.node(argument)?.span;
        let value = match self.expect_number(argument, value, argument_span)? {
            Number::Int(value) => value,
            Number::Float(value) => {
                let rounded = op(value);
                if rounded.is_nan() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::ArithmeticOverflow {
                            id,
                            op: arithmetic_op,
                        },
                        span,
                    ));
                }
                if rounded <= i64::MIN as f64 {
                    i64::MIN
                } else if rounded >= I64_MAX_EXCLUSIVE_AS_F64 {
                    i64::MAX
                } else {
                    rounded as i64
                }
            }
        };
        Ok(Value::int(value))
    }

    fn eval_seq_primop(&mut self, first: IrId, second: IrId) -> Result<Value, TreeWalkError> {
        let first_span = self.node(first)?.span;
        let value = self.eval_node(first)?;
        self.consume_suspended_lazy_identity_thunk(first, first_span, value)?;
        self.eval_lazy_node(second)
    }

    fn eval_deep_seq_primop(&mut self, first: IrId, second: IrId) -> Result<Value, TreeWalkError> {
        let first_span = self.node(first)?.span;
        let value = self.eval_node(first)?;
        if !self.consume_suspended_lazy_identity_thunk(first, first_span, value)? {
            let mut visited = Vec::new();
            self.deep_force_value(first, first_span, value, &mut visited)?;
        }
        self.eval_lazy_node(second)
    }

    fn deep_force_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        visited: &mut Vec<(ValueTag, u64)>,
    ) -> Result<(), TreeWalkError> {
        let value = self.force_value(id, span, value)?;
        let tag = value.tag();
        if !matches!(tag, ValueTag::List | ValueTag::Attrs) {
            return Ok(());
        }

        let key = (tag, value.payload_bits());
        if visited.contains(&key) {
            return Ok(());
        }
        let len = visited.len() + 1;
        visited.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        visited.push(key);

        match tag {
            ValueTag::List => {
                let elements = {
                    let list = self.heap.get_list(value).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                    Self::clone_list_elements(id, span, list)?
                };
                for element in elements {
                    self.deep_force_value(id, span, element, visited)?;
                }
            }
            ValueTag::Attrs => {
                let values = {
                    let attrs = self.heap.get_attrs(value).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                    let mut values = Vec::new();
                    values.try_reserve_exact(attrs.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: attrs.len(),
                            },
                            span,
                        )
                    })?;
                    for entry in attrs.iter_source_order() {
                        values.push(entry.value);
                    }
                    values
                };
                for value in values {
                    self.deep_force_value(id, span, value, visited)?;
                }
            }
            _ => unreachable!("deepSeq only traverses list and attrset values"),
        }

        Ok(())
    }

    fn eval_has_context_primop(
        &self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "string",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        Ok(Value::bool(string.has_context()))
    }

    fn eval_get_context_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "string",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let groups = {
            let string = self.heap.get_string(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let mut groups: Vec<ReflectedContextGroup> = Vec::new();
            groups
                .try_reserve_exact(string.context().len())
                .map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Attr {
                            id,
                            source: AttrError::AllocationFailed {
                                entries: string.context().len(),
                            },
                        },
                        span,
                    )
                })?;
            for element in string.context() {
                let path = Self::copy_bytes_for_node(id, span, element.path())?;
                let group_index = if groups
                    .last()
                    .is_some_and(|group| group.path.as_slice() == path.as_slice())
                {
                    groups.len() - 1
                } else {
                    groups.push(ReflectedContextGroup::new(path));
                    groups.len() - 1
                };
                let Some(group) = groups.get_mut(group_index) else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::InvalidStringContext { id },
                        span,
                    ));
                };
                match element.kind() {
                    ContextKind::OpaquePath => group.path_flag = true,
                    ContextKind::SingleOutput => {
                        let output = element.output().ok_or_else(|| {
                            TreeWalkError::new(TreeWalkErrorKind::InvalidStringContext { id }, span)
                        })?;
                        let len = group.outputs.len().checked_add(1).ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::List {
                                    id,
                                    source: NixListError::LengthOverflow {
                                        left: group.outputs.len(),
                                        right: 1,
                                    },
                                },
                                span,
                            )
                        })?;
                        group.outputs.try_reserve_exact(1).map_err(|_| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::ListAllocationFailed { id, len },
                                span,
                            )
                        })?;
                        group
                            .outputs
                            .push(Self::copy_bytes_for_node(id, span, output)?);
                    }
                    ContextKind::DeepDerivation => group.all_outputs = true,
                }
            }
            groups
        };

        let mut entries = Vec::new();
        entries.try_reserve_exact(groups.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: groups.len(),
                    },
                },
                span,
            )
        })?;
        for group in groups {
            let symbol = self.symbols.intern(&group.path).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SymbolIntern {
                        id,
                        source: source.kind().clone(),
                    },
                    span,
                )
            })?;
            let value = self.alloc_reflected_context_group(id, span, group)?;
            entries.push(AttrEntry::new(symbol, value));
        }
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_get_env_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let name = self.context_free_string_bytes(argument, argument_span, value, "getEnv")?;
        let env_value = self.options.env_var(&name).unwrap_or_default().to_vec();
        self.alloc_static_string(id, span, &env_value)
    }

    fn eval_path_exists_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let must_be_dir = self.path_exists_requires_directory(argument, argument_span, value)?;
        let path = self.coerce_to_path_bytes(argument, argument_span, value, "pathExists")?;
        let metadata = if must_be_dir {
            fs::metadata(Path::new(OsStr::from_bytes(&path)))
        } else {
            fs::symlink_metadata(Path::new(OsStr::from_bytes(
                path_without_trailing_path_markers(&path),
            )))
        };
        match metadata {
            Ok(metadata) => Ok(Value::bool(!must_be_dir || metadata.is_dir())),
            Err(source)
                if matches!(
                    source.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(Value::bool(false))
            }
            Err(source) => Err(TreeWalkError::new(
                TreeWalkErrorKind::PathStat {
                    id: argument,
                    path,
                    message: source.to_string(),
                },
                argument_span,
            )),
        }
    }

    fn path_exists_requires_directory(
        &self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Ok(false);
        }
        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        Ok(string.bytes().ends_with(b"/") || string.bytes().ends_with(b"/."))
    }

    fn eval_read_dir_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let path = self.coerce_to_path_bytes(argument, argument_span, value, "readDir")?;
        let entries = fs::read_dir(Path::new(OsStr::from_bytes(&path))).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::DirectoryRead {
                    id: argument,
                    path: path.clone(),
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        let mut attrs = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DirectoryRead {
                        id: argument,
                        path: path.clone(),
                        message: source.to_string(),
                    },
                    argument_span,
                )
            })?;
            let file_name = entry.file_name();
            let name = file_name.as_bytes();
            let symbol = self.symbols.intern(name).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SymbolIntern {
                        id,
                        source: source.kind().clone(),
                    },
                    span,
                )
            })?;
            let file_type = entry.file_type().map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DirectoryRead {
                        id: argument,
                        path: entry.path().as_os_str().as_bytes().to_vec(),
                        message: source.to_string(),
                    },
                    argument_span,
                )
            })?;
            let value = self.alloc_static_string(id, span, file_type_name(file_type))?;
            attrs.push(AttrEntry::new(symbol, value));
        }
        let attrs = FlatAttrs::new(attrs, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_read_file_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let path = self.coerce_to_path_bytes(argument, argument_span, value, "readFile")?;
        let contents = fs::read(Path::new(OsStr::from_bytes(&path))).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FileRead {
                    id: argument,
                    path: path.clone(),
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        if contents.contains(&0) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FileReadContainsNul { id: argument, path },
                argument_span,
            ));
        }
        self.alloc_static_string(id, span, &contents)
    }

    fn eval_read_file_type_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let path = self.coerce_to_path_bytes(argument, argument_span, value, "readFileType")?;
        let stat_path = path_without_trailing_path_markers(&path);
        let file_type =
            fs::symlink_metadata(Path::new(OsStr::from_bytes(stat_path))).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::PathStat {
                        id: argument,
                        path: path.clone(),
                        message: source.to_string(),
                    },
                    argument_span,
                )
            })?;
        self.alloc_static_string(id, span, file_type_name(file_type.file_type()))
    }

    fn alloc_reflected_context_group(
        &mut self,
        id: IrId,
        span: Span,
        group: ReflectedContextGroup,
    ) -> Result<Value, TreeWalkError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(3).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: 3 },
                },
                span,
            )
        })?;
        if group.path_flag {
            let symbol = self.intern_builtin_attr_symbol(id, b"path", span)?;
            entries.push(AttrEntry::new(symbol, Value::bool(true)));
        }
        if group.all_outputs {
            let symbol = self.intern_builtin_attr_symbol(id, b"allOutputs", span)?;
            entries.push(AttrEntry::new(symbol, Value::bool(true)));
        }
        if !group.outputs.is_empty() {
            let mut outputs = Vec::new();
            outputs
                .try_reserve_exact(group.outputs.len())
                .map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: group.outputs.len(),
                        },
                        span,
                    )
                })?;
            for output in group.outputs {
                outputs.push(self.alloc_static_string(id, span, &output)?);
            }
            let outputs = self
                .heap
                .alloc_list(NixList::new(outputs))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
            let symbol = self.intern_builtin_attr_symbol(id, b"outputs", span)?;
            entries.push(AttrEntry::new(symbol, outputs));
        }
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn copy_bytes_for_node(id: IrId, span: Span, bytes: &[u8]) -> Result<Vec<u8>, TreeWalkError> {
        let mut copied = Vec::new();
        copied.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        copied.extend_from_slice(bytes);
        Ok(copied)
    }

    fn absolute_path_bytes_for_node(
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let raw = Path::new(OsStr::from_bytes(bytes));
        if !raw.is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: Self::copy_bytes_for_node(id, span, bytes)?,
                },
                span,
            ));
        }
        let path = Self::normalize_path(raw.to_path_buf());
        Self::copy_bytes_for_node(id, span, path.as_os_str().as_bytes())
    }

    fn normalize_path(path: PathBuf) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if !normalized.pop() && !normalized.has_root() {
                        normalized.push("..");
                    }
                }
                Component::Normal(part) => normalized.push(part),
                Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
            }
        }
        if normalized.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            normalized
        }
    }

    fn extend_bytes_for_node(
        id: IrId,
        span: Span,
        target: &mut Vec<u8>,
        bytes: &[u8],
    ) -> Result<(), TreeWalkError> {
        let len = target.len().checked_add(bytes.len()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        target.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        target.extend_from_slice(bytes);
        Ok(())
    }

    fn eval_add_drv_output_dependencies_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let context = string.context();
            if context.len() != 1 {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextElementCount {
                        id: argument,
                        len: context.len(),
                    },
                    argument_span,
                ));
            }
            let Some(element) = context.elements().first() else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextElementCount {
                        id: argument,
                        len: 0,
                    },
                    argument_span,
                ));
            };
            if let ContextKind::SingleOutput = element.kind() {
                let output = element.output().ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidStringContext { id: argument },
                        argument_span,
                    )
                })?;
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextDerivationOutput {
                        id: argument,
                        output: Self::copy_bytes_for_node(argument, argument_span, output)?,
                    },
                    argument_span,
                ));
            }
            let path = Self::copy_bytes_for_node(argument, argument_span, element.path())?;
            if !path.ends_with(b".drv") {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextPathNotDerivation { id: argument, path },
                    argument_span,
                ));
            }
            let bytes = Self::copy_bytes_for_node(argument, argument_span, string.bytes())?;
            let element = ContextElement::deep_derivation(path).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let context = StringContext::singleton(element).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            NixString::new(bytes, context)
        };
        self.heap.alloc_string(result).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })
    }

    fn eval_unsafe_discard_output_dependency_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let mut elements = Vec::new();
            elements
                .try_reserve_exact(string.context().len())
                .map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source: NixStringError::ContextAllocationFailed {
                                len: string.context().len(),
                            },
                        },
                        argument_span,
                    )
                })?;
            for element in string.context() {
                let path = Self::copy_bytes_for_node(argument, argument_span, element.path())?;
                let rewritten = match element.kind() {
                    ContextKind::OpaquePath | ContextKind::DeepDerivation => {
                        ContextElement::opaque_path(path)
                    }
                    ContextKind::SingleOutput => {
                        let output = element.output().ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::InvalidStringContext { id: argument },
                                argument_span,
                            )
                        })?;
                        ContextElement::single_output(
                            path,
                            Self::copy_bytes_for_node(argument, argument_span, output)?,
                        )
                    }
                }
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                elements.push(rewritten);
            }
            let bytes = Self::copy_bytes_for_node(argument, argument_span, string.bytes())?;
            NixString::new(bytes, StringContext::new(elements))
        };
        self.heap.alloc_string(result).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })
    }

    fn eval_unsafe_discard_string_context_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            string.discard_context().map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?
        };
        self.heap.alloc_string(result).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })
    }

    fn eval_string_length_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let string = self.heap.get_string(string).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        Ok(Value::int(string.len() as i64))
    }

    fn eval_substring_primop(
        &mut self,
        start: IrId,
        len: IrId,
        string_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let start_span = self.node(start)?.span;
        let start_offset = self.eval_int_node(start)? as u32 as i32;
        // C++ Nix truncates to the builtin's signed 32-bit start parameter
        // before reporting the negative-start class.
        if start_offset < 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::NegativeSubstringStart {
                    id: start,
                    start: start_offset.into(),
                },
                start_span,
            ));
        }

        let len = self.eval_int_node(len)? as u32 as usize;
        // Length uses the builtin's unsigned 32-bit parameter, so large and
        // negative Nix integers wrap before substring clamping.

        let string_span = self.node(string_id)?.span;
        let value = self.eval_node(string_id)?;
        let string = self.coerce_to_string(string_id, value, string_span)?;
        let result = {
            let string = self.heap.get_string(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_id,
                        source,
                    },
                    string_span,
                )
            })?;
            string
                .substring_preserve_context(start_offset as usize, len)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: string_id,
                            source,
                        },
                        string_span,
                    )
                })?
        };
        self.heap.alloc_string(result).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: string_id,
                    source,
                },
                string_span,
            )
        })
    }

    fn eval_replace_strings_primop(
        &mut self,
        id: IrId,
        span: Span,
        from_id: IrId,
        to_id: IrId,
        string_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let from_span = self.node(from_id)?.span;
        let from_value = self.eval_node(from_id)?;
        if from_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: from_id,
                    expected: "list",
                    actual: from_value.tag(),
                },
                from_span,
            ));
        }
        let from_values = {
            let from = self.heap.get_list(from_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: from_id,
                        source,
                    },
                    from_span,
                )
            })?;
            let mut values = Vec::new();
            values.try_reserve_exact(from.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: from_id,
                        len: from.len(),
                    },
                    from_span,
                )
            })?;
            values.extend_from_slice(from.as_slice());
            values
        };

        let to_span = self.node(to_id)?.span;
        let to_value = self.eval_node(to_id)?;
        if to_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: to_id,
                    expected: "list",
                    actual: to_value.tag(),
                },
                to_span,
            ));
        }
        let to_values = {
            let to = self.heap.get_list(to_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id: to_id, source }, to_span)
            })?;
            let mut values = Vec::new();
            values.try_reserve_exact(to.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: to_id,
                        len: to.len(),
                    },
                    to_span,
                )
            })?;
            values.extend_from_slice(to.as_slice());
            values
        };

        if from_values.len() != to_values.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ReplaceStringsLengthMismatch {
                    id,
                    from_len: from_values.len(),
                    to_len: to_values.len(),
                },
                span,
            ));
        }

        let mut patterns = Vec::new();
        patterns.try_reserve_exact(from_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: from_values.len(),
                },
                span,
            )
        })?;
        for (from, replacement) in from_values.into_iter().zip(to_values) {
            let from = self.force_value(from_id, from_span, from)?;
            if from.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: from_id,
                        expected: "string",
                        actual: from.tag(),
                    },
                    from_span,
                ));
            }
            let from = {
                let string = self.heap.get_string(from).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: from_id,
                            source,
                        },
                        from_span,
                    )
                })?;
                Self::copy_bytes_for_node(from_id, from_span, string.bytes())?
            };
            patterns.push(ReplaceStringPattern { from, replacement });
        }

        let string_span = self.node(string_id)?.span;
        let string_value = self.eval_node(string_id)?;
        if string_value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: string_id,
                    expected: "string",
                    actual: string_value.tag(),
                },
                string_span,
            ));
        }
        let (source, context) = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_id,
                        source,
                    },
                    string_span,
                )
            })?;
            let source = Self::copy_bytes_for_node(string_id, string_span, string.bytes())?;
            let context = string
                .context()
                .union(&StringContext::empty())
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: string_id,
                            source,
                        },
                        string_span,
                    )
                })?;
            (source, context)
        };

        let result =
            self.replace_strings_bytes(id, span, to_id, to_span, &source, context, &patterns)?;
        self.heap
            .alloc_string(result)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn replace_strings_bytes(
        &mut self,
        id: IrId,
        span: Span,
        to_id: IrId,
        to_span: Span,
        source: &[u8],
        mut context: StringContext,
        patterns: &[ReplaceStringPattern],
    ) -> Result<NixString, TreeWalkError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(source.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: source.len(),
                },
                span,
            )
        })?;

        let mut offset = 0;
        while offset <= source.len() {
            let matched = patterns
                .iter()
                .position(|pattern| source[offset..].starts_with(&pattern.from));
            let Some(index) = matched else {
                if offset == source.len() {
                    break;
                }
                Self::extend_bytes_for_node(id, span, &mut bytes, &source[offset..offset + 1])?;
                offset += 1;
                continue;
            };

            let replacement =
                self.force_replace_string(to_id, to_span, patterns[index].replacement)?;
            Self::extend_bytes_for_node(id, span, &mut bytes, &replacement.bytes)?;
            context = context.union(&replacement.context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?;

            let consumed = patterns[index].from.len();
            if consumed == 0 {
                if offset == source.len() {
                    break;
                }
                Self::extend_bytes_for_node(id, span, &mut bytes, &source[offset..offset + 1])?;
                offset += 1;
            } else {
                offset += consumed;
            }
        }

        Ok(NixString::new(bytes, context))
    }

    fn force_replace_string(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<ReplaceStringReplacement, TreeWalkError> {
        let value = self.force_value(id, span, value)?;
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        let string = self
            .heap
            .get_string(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let bytes = Self::copy_bytes_for_node(id, span, string.bytes())?;
        let context = string
            .context()
            .union(&StringContext::empty())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(ReplaceStringReplacement { bytes, context })
    }

    fn eval_concat_strings_sep_primop(
        &mut self,
        id: IrId,
        span: Span,
        separator_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let separator_span = self.node(separator_id)?.span;
        let separator_value = self.eval_node(separator_id)?;
        if separator_value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: separator_id,
                    expected: "string",
                    actual: separator_value.tag(),
                },
                separator_span,
            ));
        }
        let (separator_bytes, separator_context) = {
            let separator = self.heap.get_string(separator_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: separator_id,
                        source,
                    },
                    separator_span,
                )
            })?;
            let bytes = Self::copy_bytes_for_node(separator_id, separator_span, separator.bytes())?;
            let context = separator
                .context()
                .union(&StringContext::empty())
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: separator_id,
                            source,
                        },
                        separator_span,
                    )
                })?;
            (bytes, context)
        };

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: list_id,
                        len: list.len(),
                    },
                    list_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };

        let result = self.concat_strings_sep_values(
            id,
            span,
            list_id,
            list_span,
            &separator_bytes,
            separator_context,
            &elements,
        )?;
        self.heap
            .alloc_string(result)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn concat_strings_sep_values(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        separator: &[u8],
        mut context: StringContext,
        elements: &[Value],
    ) -> Result<NixString, TreeWalkError> {
        let mut bytes = Vec::new();
        for (index, element) in elements.iter().copied().enumerate() {
            let element = self.force_value(list_id, list_span, element)?;
            let element = self.coerce_to_string(list_id, element, list_span)?;
            let (element_bytes, element_context) = {
                let string = self.heap.get_string(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: list_id,
                            source,
                        },
                        list_span,
                    )
                })?;
                let bytes = Self::copy_bytes_for_node(list_id, list_span, string.bytes())?;
                let context =
                    string
                        .context()
                        .union(&StringContext::empty())
                        .map_err(|source| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::String {
                                    id: list_id,
                                    source,
                                },
                                list_span,
                            )
                        })?;
                (bytes, context)
            };
            if index > 0 {
                Self::extend_bytes_for_node(id, span, &mut bytes, separator)?;
            }
            Self::extend_bytes_for_node(id, span, &mut bytes, &element_bytes)?;
            context = context.union(&element_context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?;
        }

        Ok(NixString::new(bytes, context))
    }

    fn eval_base_name_of_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let (start, len) = base_name_range(string.bytes());
            string
                .substring_preserve_context(start, len)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?
        };
        self.heap.alloc_string(result).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })
    }

    fn eval_dir_of_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            match dir_name_range(string.bytes()) {
                Some((start, len)) => {
                    string
                        .substring_preserve_context(start, len)
                        .map_err(|source| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::String {
                                    id: argument,
                                    source,
                                },
                                argument_span,
                            )
                        })?
                }
                None => context_free_dot_string(argument, argument_span)?,
            }
        };
        self.heap.alloc_string(result).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })
    }

    fn eval_parse_drv_name_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "string",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let bytes = {
            let string = self.heap.get_string(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(string.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id: argument,
                        len: string.len(),
                    },
                    argument_span,
                )
            })?;
            bytes.extend_from_slice(string.bytes());
            bytes
        };
        let (name_end, version_start) = parse_drv_name_split(&bytes);
        let name = self.alloc_static_string(id, span, &bytes[..name_end])?;
        let version = self.alloc_static_string(id, span, &bytes[version_start..])?;
        let name_key = self.intern_builtin_attr_symbol(id, b"name", span)?;
        let version_key = self.intern_builtin_attr_symbol(id, b"version", span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(2).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len: 2 }, span)
        })?;
        entries.push(AttrEntry::new(name_key, name));
        entries.push(AttrEntry::new(version_key, version));
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_split_version_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let bytes =
            self.context_free_string_bytes(argument, argument_span, value, "splitVersion")?;
        let len = SplitVersionRanges::new(&bytes).count();
        let mut elements = Vec::new();
        elements.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        for (start, end) in SplitVersionRanges::new(&bytes) {
            elements.push(self.alloc_static_string(id, span, &bytes[start..end])?);
        }
        self.heap
            .alloc_list(NixList::new(elements))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_compare_versions_primop(
        &mut self,
        left_id: IrId,
        right_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left_span = self.node(left_id)?.span;
        let left = self.eval_node(left_id)?;
        let left = self.context_free_string_bytes(left_id, left_span, left, "compareVersions")?;
        let right_span = self.node(right_id)?.span;
        let right = self.eval_node(right_id)?;
        let right =
            self.context_free_string_bytes(right_id, right_span, right, "compareVersions")?;
        Ok(Value::int(compare_version_bytes(&left, &right)))
    }

    fn eval_hash_string_primop(
        &mut self,
        id: IrId,
        span: Span,
        algorithm_id: IrId,
        string_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let algorithm_span = self.node(algorithm_id)?.span;
        let algorithm = self.eval_node(algorithm_id)?;
        let algorithm =
            self.eval_hash_algorithm(algorithm_id, algorithm_span, algorithm, "hashString")?;

        let string_span = self.node(string_id)?.span;
        let string = self.eval_node(string_id)?;
        if string.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: string_id,
                    expected: "string",
                    actual: string.tag(),
                },
                string_span,
            ));
        }
        self.eval_hash_string_value(id, span, string_id, string_span, string, algorithm)
    }

    fn eval_hash_string_value(
        &mut self,
        id: IrId,
        span: Span,
        string_id: IrId,
        string_span: Span,
        string: Value,
        algorithm: HashStringAlgorithm,
    ) -> Result<Value, TreeWalkError> {
        let digest = {
            let string = self.heap.get_string(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_id,
                        source,
                    },
                    string_span,
                )
            })?;
            Self::hash_bytes(string.bytes(), algorithm)
        };
        self.alloc_hash_digest(id, span, &digest)
    }

    fn eval_hash_file_primop(
        &mut self,
        id: IrId,
        span: Span,
        algorithm_id: IrId,
        path_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let algorithm_span = self.node(algorithm_id)?.span;
        let algorithm = self.eval_node(algorithm_id)?;
        let algorithm =
            self.eval_hash_algorithm(algorithm_id, algorithm_span, algorithm, "hashFile")?;

        let path_span = self.node(path_id)?.span;
        let path_value = self.eval_node(path_id)?;
        let path = self.coerce_to_path_bytes(path_id, path_span, path_value, "hashFile")?;
        let contents = fs::read(Path::new(OsStr::from_bytes(&path))).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FileRead {
                    id: path_id,
                    path: path.clone(),
                    message: source.to_string(),
                },
                path_span,
            )
        })?;
        let digest = Self::hash_bytes(&contents, algorithm);
        self.alloc_hash_digest(id, span, &digest)
    }

    fn eval_convert_hash_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "attrs",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }

        let hash_value =
            self.required_attr_value_by_name(argument, value, HASH_ATTR, argument_span)?;
        let hash_value = self.force_value(argument, argument_span, hash_value)?;
        let hash =
            self.context_free_string_bytes(argument, argument_span, hash_value, "convertHash")?;

        let expected_algorithm = if let Some(algorithm_value) =
            self.attr_value_by_name(argument, value, HASH_ALGO_ATTR, argument_span)?
        {
            let algorithm_value = self.force_value(argument, argument_span, algorithm_value)?;
            Some(self.eval_hash_algorithm(
                argument,
                argument_span,
                algorithm_value,
                "convertHash",
            )?)
        } else {
            None
        };

        let format_value =
            self.required_attr_value_by_name(argument, value, TO_HASH_FORMAT_ATTR, argument_span)?;
        let format_value = self.force_value(argument, argument_span, format_value)?;
        let format =
            self.eval_convert_hash_format(argument, argument_span, format_value, "convertHash")?;

        let (algorithm, digest) =
            self.decode_convert_hash(argument, argument_span, &hash, expected_algorithm)?;
        let bytes = Self::encode_convert_hash_digest(id, span, algorithm, format, &digest)?;
        self.heap
            .alloc_string(NixString::from_bytes(bytes))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn hash_bytes(bytes: &[u8], algorithm: HashStringAlgorithm) -> Vec<u8> {
        match algorithm {
            HashStringAlgorithm::Md5 => Md5::digest(bytes).to_vec(),
            HashStringAlgorithm::Sha1 => Sha1::digest(bytes).to_vec(),
            HashStringAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
            HashStringAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }

    fn alloc_hash_digest(
        &mut self,
        id: IrId,
        span: Span,
        digest: &[u8],
    ) -> Result<Value, TreeWalkError> {
        let bytes = Self::lower_hex_bytes(id, span, digest)?;
        self.heap
            .alloc_string(NixString::from_bytes(bytes))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_hash_algorithm(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<HashStringAlgorithm, TreeWalkError> {
        let algorithm_bytes = self.context_free_string_bytes(id, span, value, op)?;
        HashStringAlgorithm::from_bytes(&algorithm_bytes).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::UnknownHashAlgorithm {
                    id,
                    algorithm: algorithm_bytes,
                },
                span,
            )
        })
    }

    fn required_attr_value_by_name(
        &mut self,
        id: IrId,
        attrs_value: Value,
        name: &[u8],
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let symbol = self.intern_builtin_attr_symbol(id, name, span)?;
        let attrs = self
            .heap
            .get_attrs(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        attrs.get(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::MissingAttribute { id, symbol }, span)
        })
    }

    fn eval_convert_hash_format(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<ConvertHashFormat, TreeWalkError> {
        let format_bytes = self.context_free_string_bytes(id, span, value, op)?;
        ConvertHashFormat::from_bytes(&format_bytes).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::UnknownHashFormat {
                    id,
                    format: format_bytes,
                },
                span,
            )
        })
    }

    fn decode_convert_hash(
        &self,
        argument: IrId,
        argument_span: Span,
        hash: &[u8],
        expected_algorithm: Option<HashStringAlgorithm>,
    ) -> Result<(HashStringAlgorithm, Vec<u8>), TreeWalkError> {
        if let Some((algorithm, input_format, payload)) =
            Self::split_convert_hash_typed_input(argument, argument_span, hash)?
        {
            if let Some(expected) = expected_algorithm {
                if algorithm != expected {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::HashAlgorithmMismatch {
                            id: argument,
                            hash: Self::copy_bytes_for_node(argument, argument_span, hash)?,
                            expected: Self::copy_bytes_for_node(
                                argument,
                                argument_span,
                                expected.name(),
                            )?,
                        },
                        argument_span,
                    ));
                }
            }

            let digest = match input_format {
                ConvertHashInputFormat::Sri => {
                    self.decode_sri_hash_payload(argument, argument_span, hash, algorithm, payload)?
                }
                ConvertHashInputFormat::Typed => {
                    self.decode_hash_payload(argument, argument_span, hash, algorithm, payload)?
                }
            };
            return Ok((algorithm, digest));
        }

        let Some(algorithm) = expected_algorithm else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::HashAlgorithmRequired {
                    id: argument,
                    hash: Self::copy_bytes_for_node(argument, argument_span, hash)?,
                },
                argument_span,
            ));
        };
        let digest = self.decode_hash_payload(argument, argument_span, hash, algorithm, hash)?;
        Ok((algorithm, digest))
    }

    fn split_convert_hash_typed_input(
        id: IrId,
        span: Span,
        hash: &[u8],
    ) -> Result<Option<(HashStringAlgorithm, ConvertHashInputFormat, &[u8])>, TreeWalkError> {
        let sri_separator = hash.iter().position(|byte| *byte == b'-');
        let typed_separator = hash.iter().position(|byte| *byte == b':');
        let Some((separator, input_format)) = (match (sri_separator, typed_separator) {
            (Some(sri), Some(typed)) if sri < typed => Some((sri, ConvertHashInputFormat::Sri)),
            (Some(_), Some(typed)) => Some((typed, ConvertHashInputFormat::Typed)),
            (Some(sri), None) => Some((sri, ConvertHashInputFormat::Sri)),
            (None, Some(typed)) => Some((typed, ConvertHashInputFormat::Typed)),
            (None, None) => None,
        }) else {
            return Ok(None);
        };
        let algorithm = HashStringAlgorithm::from_bytes(&hash[..separator]).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::UnknownHashAlgorithm {
                    id,
                    algorithm: hash[..separator].to_vec(),
                },
                span,
            )
        })?;
        Ok(Some((algorithm, input_format, &hash[separator + 1..])))
    }

    fn decode_sri_hash_payload(
        &self,
        id: IrId,
        span: Span,
        hash: &[u8],
        algorithm: HashStringAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let digest_len = algorithm.digest_len();
        let padded_len = Self::base64_encoded_len(digest_len);
        let unpadded_len = Self::base64_unpadded_encoded_len(digest_len);
        let decoded = if payload.len() == padded_len {
            base64::engine::general_purpose::STANDARD.decode(payload)
        } else if payload.len() == unpadded_len {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload)
        } else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSriHash {
                    id,
                    hash: hash.to_vec(),
                },
                span,
            ));
        }
        .map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSriHash {
                    id,
                    hash: hash.to_vec(),
                },
                span,
            )
        })?;
        self.check_hash_digest_len(id, span, hash, algorithm, decoded)
    }

    fn decode_hash_payload(
        &self,
        id: IrId,
        span: Span,
        hash: &[u8],
        algorithm: HashStringAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let digest_len = algorithm.digest_len();
        if payload.len()
            == digest_len.checked_mul(2).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?
        {
            return Self::decode_base16_hash(id, span, hash, payload);
        }
        if payload.len() == Self::nix_base32_encoded_len(digest_len) {
            return Self::decode_nix_base32_hash(id, span, hash, payload);
        }
        let base64_len = Self::base64_encoded_len(digest_len);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| {
                if payload.len() == base64_len {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidBase64Hash {
                            id,
                            hash: hash.to_vec(),
                        },
                        span,
                    )
                } else {
                    TreeWalkError::new(
                        TreeWalkErrorKind::HashWrongLength {
                            id,
                            hash: hash.to_vec(),
                            algorithm: algorithm.name().to_vec(),
                        },
                        span,
                    )
                }
            })?;
        self.check_hash_digest_len(id, span, hash, algorithm, decoded)
    }

    fn check_hash_digest_len(
        &self,
        id: IrId,
        span: Span,
        hash: &[u8],
        algorithm: HashStringAlgorithm,
        digest: Vec<u8>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        if digest.len() == algorithm.digest_len() {
            Ok(digest)
        } else {
            Err(TreeWalkError::new(
                TreeWalkErrorKind::HashWrongLength {
                    id,
                    hash: hash.to_vec(),
                    algorithm: algorithm.name().to_vec(),
                },
                span,
            ))
        }
    }

    fn decode_base16_hash(
        id: IrId,
        span: Span,
        hash: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut out = Vec::new();
        out.try_reserve_exact(payload.len() / 2).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: payload.len() / 2,
                },
                span,
            )
        })?;
        for pair in payload.chunks_exact(2) {
            let high = Self::hex_digit(pair[0]).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidBase16Hash {
                        id,
                        hash: hash.to_vec(),
                    },
                    span,
                )
            })?;
            let low = Self::hex_digit(pair[1]).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidBase16Hash {
                        id,
                        hash: hash.to_vec(),
                    },
                    span,
                )
            })?;
            out.push((high << 4) | low);
        }
        Ok(out)
    }

    fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    fn decode_nix_base32_hash(
        id: IrId,
        span: Span,
        hash: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        Self::decode_nix_base32(id, span, payload)?.ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidNix32Hash {
                    id,
                    hash: hash.to_vec(),
                },
                span,
            )
        })
    }

    fn decode_nix_base32(
        id: IrId,
        span: Span,
        encoded: &[u8],
    ) -> Result<Option<Vec<u8>>, TreeWalkError> {
        let len = encoded
            .len()
            .checked_mul(5)
            .map(|bits| bits / 8)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        out.resize(len, 0);
        for (n, byte) in encoded.iter().rev().enumerate() {
            let Some(digit) = NIX_BASE32.iter().position(|digit| digit == byte) else {
                return Ok(None);
            };
            let digit = digit as u16;
            let bit = n * 5;
            let i = bit / 8;
            let j = bit % 8;
            let Some(current) = out.get_mut(i) else {
                return Ok(None);
            };
            *current |= (digit << j) as u8;
            let carry = digit >> (8 - j);
            match out.get_mut(i + 1) {
                Some(next) => *next |= carry as u8,
                None if carry != 0 => return Ok(None),
                None => {}
            }
        }
        Ok(Some(out))
    }

    fn encode_convert_hash_digest(
        id: IrId,
        span: Span,
        algorithm: HashStringAlgorithm,
        format: ConvertHashFormat,
        digest: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        match format {
            ConvertHashFormat::Base16 => Self::lower_hex_bytes(id, span, digest),
            ConvertHashFormat::Nix32 => Self::encode_nix_base32(id, span, digest),
            ConvertHashFormat::Base64 => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
                Self::copy_bytes_for_node(id, span, encoded.as_bytes())
            }
            ConvertHashFormat::Sri => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
                let len = algorithm
                    .name()
                    .len()
                    .checked_add(1)
                    .and_then(|len| len.checked_add(encoded.len()))
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ByteAllocationFailed {
                                id,
                                len: usize::MAX,
                            },
                            span,
                        )
                    })?;
                let mut out = Vec::new();
                out.try_reserve_exact(len).map_err(|_| {
                    TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
                })?;
                out.extend_from_slice(algorithm.name());
                out.push(b'-');
                out.extend_from_slice(encoded.as_bytes());
                Ok(out)
            }
        }
    }

    fn encode_nix_base32(id: IrId, span: Span, bytes: &[u8]) -> Result<Vec<u8>, TreeWalkError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let len = Self::nix_base32_encoded_len(bytes.len());
        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        for n in (0..len).rev() {
            let bit = n * 5;
            let i = bit / 8;
            let j = bit % 8;
            let mut c = (bytes[i] >> j) as u16;
            if i + 1 < bytes.len() {
                c |= (bytes[i + 1] as u16) << (8 - j);
            }
            out.push(NIX_BASE32[usize::from(c & 0x1f)]);
        }
        Ok(out)
    }

    fn nix_base32_encoded_len(byte_len: usize) -> usize {
        byte_len.saturating_mul(8).div_ceil(5)
    }

    fn base64_encoded_len(byte_len: usize) -> usize {
        byte_len.div_ceil(3).saturating_mul(4)
    }

    fn base64_unpadded_encoded_len(byte_len: usize) -> usize {
        let len = (byte_len / 3).saturating_mul(4);
        match byte_len % 3 {
            0 => len,
            1 => len.saturating_add(2),
            2 => len.saturating_add(3),
            _ => len,
        }
    }

    #[cfg(test)]
    fn eval_hash_string_primop_with_string_value(
        &mut self,
        id: IrId,
        span: Span,
        algorithm_id: IrId,
        string_id: IrId,
        string_span: Span,
        string: Value,
    ) -> Result<Value, TreeWalkError> {
        let algorithm_span = self.node(algorithm_id)?.span;
        let algorithm = self.eval_node(algorithm_id)?;
        let algorithm =
            self.eval_hash_algorithm(algorithm_id, algorithm_span, algorithm, "hashString")?;
        self.eval_hash_string_value(id, span, string_id, string_span, string, algorithm)
    }

    fn lower_hex_bytes(id: IrId, span: Span, digest: &[u8]) -> Result<Vec<u8>, TreeWalkError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let len = digest.len().checked_mul(2).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        for byte in digest {
            bytes.push(HEX[usize::from(byte >> 4)]);
            bytes.push(HEX[usize::from(byte & 0x0f)]);
        }
        Ok(bytes)
    }

    #[cfg(test)]
    fn eval_compare_versions_values(
        &self,
        left_id: IrId,
        left_span: Span,
        left: Value,
        right_id: IrId,
        right_span: Span,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let left = self.context_free_string_bytes(left_id, left_span, left, "compareVersions")?;
        let right =
            self.context_free_string_bytes(right_id, right_span, right, "compareVersions")?;
        Ok(Value::int(compare_version_bytes(&left, &right)))
    }

    fn eval_from_json_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let bytes = self.context_free_string_bytes(argument, argument_span, value, "fromJSON")?;
        let json: JsonValue = serde_json::from_slice(&bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::JsonParse {
                    id: argument,
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        self.value_from_json(argument, argument_span, json)
    }

    fn value_from_json(
        &mut self,
        id: IrId,
        span: Span,
        value: JsonValue,
    ) -> Result<Value, TreeWalkError> {
        match value {
            JsonValue::Null => Ok(Value::null()),
            JsonValue::Bool(value) => Ok(Value::bool(value)),
            JsonValue::Number(value) => {
                if let Some(value) = value.as_i64() {
                    Ok(Value::int(value))
                } else if let Some(value) = value.as_u64() {
                    Ok(Value::int(value as i64))
                } else if let Some(value) = value.as_f64() {
                    Ok(Value::float(value))
                } else {
                    Err(TreeWalkError::new(
                        TreeWalkErrorKind::JsonNumberUnsupported { id },
                        span,
                    ))
                }
            }
            JsonValue::String(value) => self.alloc_static_string(id, span, value.as_bytes()),
            JsonValue::Array(values) => {
                let mut elements = Vec::new();
                elements.try_reserve_exact(values.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: values.len(),
                        },
                        span,
                    )
                })?;
                for value in values {
                    elements.push(self.value_from_json(id, span, value)?);
                }
                self.heap
                    .alloc_list(NixList::new(elements))
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })
            }
            JsonValue::Object(values) => {
                let mut entries = Vec::new();
                entries.try_reserve_exact(values.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Attr {
                            id,
                            source: AttrError::AllocationFailed {
                                entries: values.len(),
                            },
                        },
                        span,
                    )
                })?;
                for (key, value) in values {
                    let symbol = self.symbols.intern(key.as_bytes()).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SymbolIntern {
                                id,
                                source: source.kind().clone(),
                            },
                            span,
                        )
                    })?;
                    let value = self.value_from_json(id, span, value)?;
                    entries.push(AttrEntry::new(symbol, value));
                }
                let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span)
                })?;
                self.heap.alloc_attrs(0, attrs).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })
            }
        }
    }

    fn eval_to_string_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.to_string_value(id, span, argument, argument_span, value)?;
        self.heap
            .alloc_string(string)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        if value.tag() == ValueTag::List {
            return self.list_to_string_value(id, span, value_id, value_span, value);
        }
        self.scalar_to_string_value(id, span, value_id, value_span, value)
    }

    fn list_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let mut bytes = Vec::new();
        let mut context = StringContext::empty();
        let mut fields = 0usize;
        self.append_list_to_string_fields(
            id,
            span,
            list_id,
            list_span,
            value,
            &mut bytes,
            &mut context,
            &mut fields,
        )?;
        Ok(NixString::new(bytes, context))
    }

    fn append_list_to_string_fields(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        bytes: &mut Vec<u8>,
        context: &mut StringContext,
        fields: &mut usize,
    ) -> Result<(), TreeWalkError> {
        let elements = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: list_id,
                        len: list.len(),
                    },
                    list_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };

        for element in elements {
            self.append_to_string_list(
                id, span, list_id, list_span, element, bytes, context, fields,
            )?;
        }
        Ok(())
    }

    fn append_to_string_list(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        bytes: &mut Vec<u8>,
        context: &mut StringContext,
        fields: &mut usize,
    ) -> Result<(), TreeWalkError> {
        let value = self.force_value(list_id, list_span, value)?;
        if value.tag() == ValueTag::List {
            return self.append_list_to_string_fields(
                id, span, list_id, list_span, value, bytes, context, fields,
            );
        }

        let rendered = self.scalar_to_string_value(id, span, list_id, list_span, value)?;
        Self::append_to_string_field(id, span, bytes, context, fields, rendered)
    }

    fn append_to_string_field(
        id: IrId,
        span: Span,
        bytes: &mut Vec<u8>,
        context: &mut StringContext,
        fields: &mut usize,
        field: NixString,
    ) -> Result<(), TreeWalkError> {
        if *fields > 0 {
            Self::extend_bytes_for_node(id, span, bytes, b" ")?;
        }
        *fields = fields.checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListLengthOverflow {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        Self::extend_bytes_for_node(id, span, bytes, field.bytes())?;
        *context = context
            .union(field.context())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(())
    }

    fn scalar_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        match value.tag() {
            ValueTag::String => self.clone_string_value(value_id, value_span, value),
            ValueTag::Int => Ok(NixString::from_bytes(
                (value.payload_bits() as i64).to_string().into_bytes(),
            )),
            ValueTag::Float => Ok(NixString::from_bytes(Self::to_string_float_bytes(
                f64::from_bits(value.payload_bits()),
            ))),
            ValueTag::Bool => {
                if self.expect_bool(value_id, value, value_span)? {
                    Ok(NixString::from_bytes(b"1".to_vec()))
                } else {
                    Ok(NixString::default())
                }
            }
            ValueTag::Null => Ok(NixString::default()),
            ValueTag::Attrs => self.attrs_to_string_value(id, span, value_id, value_span, value),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: value_id,
                    expected: "string",
                    actual,
                },
                value_span,
            )),
        }
    }

    fn attrs_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        attrs_value: Value,
    ) -> Result<NixString, TreeWalkError> {
        if let Some(hook) =
            self.attr_value_by_name(attrs_id, attrs_value, TO_STRING_ATTR, attrs_span)?
        {
            let hook = self.force_value(attrs_id, attrs_span, hook)?;
            let value = self.apply_lambda_value(
                attrs_id,
                attrs_span,
                attrs_id,
                hook,
                attrs_span,
                attrs_id,
                attrs_value,
            )?;
            return self.to_string_value(id, span, attrs_id, attrs_span, value);
        }

        if let Some(out_path) =
            self.attr_value_by_name(attrs_id, attrs_value, OUT_PATH_ATTR, attrs_span)?
        {
            let value = self.force_value(attrs_id, attrs_span, out_path)?;
            return self.to_string_value(id, span, attrs_id, attrs_span, value);
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::Type {
                id: attrs_id,
                expected: "string",
                actual: ValueTag::Attrs,
            },
            attrs_span,
        ))
    }

    fn clone_string_value(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let string = self
            .heap
            .get_string(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let bytes = Self::copy_bytes_for_node(id, span, string.bytes())?;
        let context = string
            .context()
            .union(&StringContext::empty())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(NixString::new(bytes, context))
    }

    fn clone_path_value(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let path = self
            .heap
            .get_path(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let bytes = Self::copy_bytes_for_node(id, span, path.bytes())?;
        Ok(NixString::from_bytes(bytes))
    }

    fn to_string_float_bytes(value: f64) -> Vec<u8> {
        if value.is_nan() {
            return b"nan".to_vec();
        }
        let value = if value == 0.0 { 0.0 } else { value };
        format!("{value:.6}").into_bytes()
    }

    fn eval_to_json_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let mut bytes = Vec::new();
        let mut context = StringContext::empty();
        self.write_json_value(
            id,
            span,
            argument,
            argument_span,
            value,
            &mut bytes,
            &mut context,
        )?;
        self.heap
            .alloc_string(NixString::new(bytes, context))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn write_json_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        context: &mut StringContext,
    ) -> Result<(), TreeWalkError> {
        match value.tag() {
            ValueTag::Null => Self::extend_bytes_for_node(id, span, out, b"null"),
            ValueTag::Bool => {
                if self.expect_bool(value_id, value, value_span)? {
                    Self::extend_bytes_for_node(id, span, out, b"true")
                } else {
                    Self::extend_bytes_for_node(id, span, out, b"false")
                }
            }
            ValueTag::Int => Self::extend_bytes_for_node(
                id,
                span,
                out,
                (value.payload_bits() as i64).to_string().as_bytes(),
            ),
            ValueTag::Float => self.write_json_float(id, span, value, out),
            ValueTag::String => {
                self.write_json_string_value(id, span, value_id, value_span, value, out, context)
            }
            ValueTag::List => {
                self.write_json_list(id, span, value_id, value_span, value, out, context)
            }
            ValueTag::Attrs => {
                self.write_json_attrs(id, span, value_id, value_span, value, out, context)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::JsonUnsupportedValue {
                    id: value_id,
                    actual,
                },
                value_span,
            )),
        }
    }

    fn write_json_float(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let value = f64::from_bits(value.payload_bits());
        if !value.is_finite() {
            return Self::extend_bytes_for_node(id, span, out, b"null");
        }
        let value = if value == 0.0 { 0.0 } else { value };
        let Some(number) = JsonNumber::from_f64(value) else {
            return Self::extend_bytes_for_node(id, span, out, b"null");
        };
        let mut bytes = number.to_string().into_bytes();
        Self::normalize_json_float_exponent(&mut bytes);
        Self::extend_bytes_for_node(id, span, out, &bytes)
    }

    fn normalize_json_float_exponent(bytes: &mut Vec<u8>) {
        let Some(exponent) = bytes.iter().position(|byte| matches!(*byte, b'e' | b'E')) else {
            return;
        };
        bytes[exponent] = b'e';
        let sign = exponent + 1;
        let digits = match bytes.get(sign).copied() {
            Some(b'+') | Some(b'-') => sign + 1,
            Some(_) => {
                bytes.insert(sign, b'+');
                sign + 1
            }
            None => return,
        };
        if bytes.len().saturating_sub(digits) == 1 {
            bytes.insert(digits, b'0');
        }
    }

    fn write_json_string_value(
        &self,
        id: IrId,
        span: Span,
        string_id: IrId,
        string_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        context: &mut StringContext,
    ) -> Result<(), TreeWalkError> {
        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: string_id,
                    source,
                },
                string_span,
            )
        })?;
        Self::write_json_string_bytes(id, span, string.bytes(), out)?;
        *context = context
            .union(string.context())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(())
    }

    fn write_json_string_bytes(
        id: IrId,
        span: Span,
        bytes: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        Self::extend_bytes_for_node(id, span, out, b"\"")?;
        for byte in bytes {
            match *byte {
                b'"' => Self::extend_bytes_for_node(id, span, out, b"\\\"")?,
                b'\\' => Self::extend_bytes_for_node(id, span, out, b"\\\\")?,
                b'\n' => Self::extend_bytes_for_node(id, span, out, b"\\n")?,
                b'\r' => Self::extend_bytes_for_node(id, span, out, b"\\r")?,
                b'\t' => Self::extend_bytes_for_node(id, span, out, b"\\t")?,
                0x08 => Self::extend_bytes_for_node(id, span, out, b"\\b")?,
                0x0c => Self::extend_bytes_for_node(id, span, out, b"\\f")?,
                0x00..=0x1f => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    Self::extend_bytes_for_node(id, span, out, b"\\u00")?;
                    Self::extend_bytes_for_node(
                        id,
                        span,
                        out,
                        &[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]],
                    )?;
                }
                byte => Self::extend_bytes_for_node(id, span, out, &[byte])?,
            }
        }
        Self::extend_bytes_for_node(id, span, out, b"\"")
    }

    fn write_json_list(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        context: &mut StringContext,
    ) -> Result<(), TreeWalkError> {
        let elements = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: list_id,
                        len: list.len(),
                    },
                    list_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };

        Self::extend_bytes_for_node(id, span, out, b"[")?;
        for (index, element) in elements.into_iter().enumerate() {
            if index > 0 {
                Self::extend_bytes_for_node(id, span, out, b",")?;
            }
            let element = self.force_value(list_id, list_span, element)?;
            self.write_json_value(id, span, list_id, list_span, element, out, context)?;
        }
        Self::extend_bytes_for_node(id, span, out, b"]")
    }

    fn write_json_attrs(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        context: &mut StringContext,
    ) -> Result<(), TreeWalkError> {
        if self
            .attr_value_by_name(attrs_id, value, TO_STRING_ATTR, attrs_span)?
            .is_some()
        {
            let string = self.coerce_to_string(attrs_id, value, attrs_span)?;
            return self
                .write_json_string_value(id, span, attrs_id, attrs_span, string, out, context);
        }

        if let Some(out_path) =
            self.attr_value_by_name(attrs_id, value, OUT_PATH_ATTR, attrs_span)?
        {
            let value = self.force_value(attrs_id, attrs_span, out_path)?;
            return self.write_json_value(id, span, attrs_id, attrs_span, value, out, context);
        }

        let entries = {
            let attrs = self.heap.get_attrs(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed {
                            entries: attrs.len(),
                        },
                    },
                    span,
                )
            })?;
            for entry in attrs.iter_lexicographic() {
                let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol {
                            id: attrs_id,
                            symbol: entry.key,
                        },
                        attrs_span,
                    )
                })?;
                entries.push((Self::copy_bytes_for_node(id, span, key)?, entry.value));
            }
            entries
        };

        Self::extend_bytes_for_node(id, span, out, b"{")?;
        for (index, (key, value)) in entries.into_iter().enumerate() {
            if index > 0 {
                Self::extend_bytes_for_node(id, span, out, b",")?;
            }
            Self::write_json_string_bytes(id, span, &key, out)?;
            Self::extend_bytes_for_node(id, span, out, b":")?;
            let value = self.force_value(attrs_id, attrs_span, value)?;
            self.write_json_value(id, span, attrs_id, attrs_span, value, out, context)?;
        }
        Self::extend_bytes_for_node(id, span, out, b"}")
    }

    fn eval_list_to_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "list",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: argument,
                        len: list.len(),
                    },
                    argument_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };

        let name_attr = self.intern_builtin_attr_symbol(id, NAME_ATTR, span)?;
        let value_attr = self.intern_builtin_attr_symbol(id, VALUE_ATTR, span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: elements.len(),
                    },
                },
                span,
            )
        })?;

        for element in elements {
            let element = self.force_value(argument, argument_span, element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    argument_span,
                ));
            }
            let name_value = {
                let attrs = self.heap.get_attrs(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                attrs.get(name_attr).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute {
                            id: argument,
                            symbol: name_attr,
                        },
                        argument_span,
                    )
                })?
            };
            let name_value = self.force_value(argument, argument_span, name_value)?;
            if name_value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "string",
                        actual: name_value.tag(),
                    },
                    argument_span,
                ));
            }
            let key = self.intern_string_value(argument, name_value, argument_span)?;
            if entries.iter().any(|entry: &AttrEntry| entry.key == key) {
                continue;
            }

            let attr_value = {
                let attrs = self.heap.get_attrs(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                attrs.get(value_attr).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute {
                            id: argument,
                            symbol: value_attr,
                        },
                        argument_span,
                    )
                })?
            };
            entries.push(AttrEntry::new(key, attr_value));
        }

        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_concat_lists_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "list",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let lists = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            Self::clone_list_elements(argument, argument_span, list)?
        };

        let mut elements = Vec::new();
        for list_value in lists {
            let list_value = self.force_value(argument, argument_span, list_value)?;
            if list_value.tag() != ValueTag::List {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "list",
                        actual: list_value.tag(),
                    },
                    argument_span,
                ));
            }
            let inner = {
                let list = self.heap.get_list(list_value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                Self::clone_list_elements(argument, argument_span, list)?
            };
            let len = elements.len().checked_add(inner.len()).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::LengthOverflow {
                            left: elements.len(),
                            right: inner.len(),
                        },
                    },
                    span,
                )
            })?;
            elements.try_reserve_exact(inner.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::AllocationFailed { len },
                    },
                    span,
                )
            })?;
            elements.extend(inner);
        }
        self.heap
            .alloc_list(NixList::new(elements))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn intern_builtin_attr_symbol(
        &mut self,
        id: IrId,
        name: &[u8],
        span: Span,
    ) -> Result<Symbol, TreeWalkError> {
        self.symbols.intern(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                span,
            )
        })
    }

    fn eval_elem_at_primop(
        &mut self,
        list_id: IrId,
        index_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let index_span = self.node(index_id)?.span;
        let index_value = self.eval_node(index_id)?;
        let index_value = self.force_value(index_id, index_span, index_value)?;
        if index_value.tag() != ValueTag::Int {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: index_id,
                    expected: "int",
                    actual: index_value.tag(),
                },
                index_span,
            ));
        }
        let index = index_value.payload_bits() as i64;
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let list = self.heap.get_list(list_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: list_id,
                    source,
                },
                list_span,
            )
        })?;
        let Some(value) = usize::try_from(index)
            .ok()
            .and_then(|index| list.get(index))
        else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ListIndexOutOfBounds {
                    id: index_id,
                    index,
                    len: list.len(),
                },
                index_span,
            ));
        };
        Ok(value)
    }

    fn eval_elem_at_primop_value(
        &mut self,
        list: EvalPrimOpArg,
        index: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let index_value = self.force_value(index.id(), index.span(), index.value())?;
        if index_value.tag() != ValueTag::Int {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: index.id(),
                    expected: "int",
                    actual: index_value.tag(),
                },
                index.span(),
            ));
        }
        let index_value = index_value.payload_bits() as i64;
        let list_value = self.force_value(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let list_value = self.heap.get_list(list_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: list.id(),
                    source,
                },
                list.span(),
            )
        })?;
        let Some(value) = usize::try_from(index_value)
            .ok()
            .and_then(|index| list_value.get(index))
        else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ListIndexOutOfBounds {
                    id: index.id(),
                    index: index_value,
                    len: list_value.len(),
                },
                index.span(),
            ));
        };
        Ok(value)
    }

    fn eval_elem_primop(
        &mut self,
        id: IrId,
        node: &IrNode,
        candidate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };
        if elements.is_empty() {
            return Ok(Value::bool(false));
        }

        let candidate_span = self.node(candidate_id)?.span;
        let candidate = self.eval_nested_equality_operand(candidate_id)?;
        for element in elements {
            if self.values_equal_nested_lazy(
                id,
                node,
                candidate_id,
                candidate_span,
                candidate,
                list_id,
                list_span,
                element,
            )? {
                return Ok(Value::bool(true));
            }
        }
        Ok(Value::bool(false))
    }

    fn eval_get_attr_primop(
        &mut self,
        id: IrId,
        span: Span,
        name_id: IrId,
        attrs_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_node(attrs_id)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }
        let selected = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            attrs.get(key)
        };
        selected.ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                span,
            )
        })
    }

    fn eval_has_attr_primop(
        &mut self,
        name_id: IrId,
        attrs_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_node(attrs_id)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }
        let has_attr = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            attrs.contains_key(key)
        };
        Ok(Value::bool(has_attr))
    }

    fn eval_attr_name_primop_argument(&mut self, id: IrId) -> Result<Symbol, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        self.intern_string_value(id, value, span)
    }

    fn eval_remove_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        names_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_node(attrs_id)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }

        let names_span = self.node(names_id)?.span;
        let names_value = self.eval_node(names_id)?;
        if names_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: names_id,
                    expected: "list",
                    actual: names_value.tag(),
                },
                names_span,
            ));
        }
        let name_values = {
            let names = self.heap.get_list(names_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: names_id,
                        source,
                    },
                    names_span,
                )
            })?;
            let mut values = Vec::new();
            values.try_reserve_exact(names.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: names_id,
                        len: names.len(),
                    },
                    names_span,
                )
            })?;
            values.extend_from_slice(names.as_slice());
            values
        };
        let mut remove = Vec::new();
        remove.try_reserve_exact(name_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: names_id,
                    len: name_values.len(),
                },
                names_span,
            )
        })?;
        for value in name_values {
            let value = self.force_value(names_id, names_span, value)?;
            if value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: names_id,
                        expected: "string",
                        actual: value.tag(),
                    },
                    names_span,
                ));
            }
            let key = self.intern_string_value(names_id, value, names_span)?;
            if !remove.contains(&key) {
                remove.push(key);
            }
        }

        let entries = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: attrs.len(),
                    },
                    span,
                )
            })?;
            for entry in attrs.entries_by_symbol() {
                if !remove.contains(&entry.key) {
                    entries.push(*entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_intersect_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        left_id: IrId,
        right_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left_span = self.node(left_id)?.span;
        let left_value = self.eval_node(left_id)?;
        if left_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: left_id,
                    expected: "attrs",
                    actual: left_value.tag(),
                },
                left_span,
            ));
        }

        let right_span = self.node(right_id)?.span;
        let right_value = self.eval_node(right_id)?;
        if right_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: right_id,
                    expected: "attrs",
                    actual: right_value.tag(),
                },
                right_span,
            ));
        }

        let left_keys = {
            let left = self.heap.get_attrs(left_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: left_id,
                        source,
                    },
                    left_span,
                )
            })?;
            let mut keys = Vec::new();
            keys.try_reserve_exact(left.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: left_id,
                        len: left.len(),
                    },
                    left_span,
                )
            })?;
            keys.extend(left.entries_by_symbol().iter().map(|entry| entry.key));
            keys
        };
        let entries = {
            let right = self.heap.get_attrs(right_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: right_id,
                        source,
                    },
                    right_span,
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(right.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: right.len(),
                    },
                    span,
                )
            })?;
            for entry in right.entries_by_symbol() {
                if left_keys.contains(&entry.key) {
                    entries.push(*entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_cat_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        name_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: list_id,
                        len: list.len(),
                    },
                    list_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };
        let mut values = Vec::new();
        values.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            let element = self.force_value(list_id, list_span, element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: list_id,
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    list_span,
                ));
            }
            let selected = {
                let attrs = self.heap.get_attrs(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: list_id,
                            source,
                        },
                        list_span,
                    )
                })?;
                attrs.get(key)
            };
            if let Some(value) = selected {
                values.push(value);
            }
        }
        self.heap
            .alloc_list(NixList::new(values))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_all_any_primop(
        &mut self,
        op: AllAnyOp,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let predicate_span = self.node(predicate_id)?.span;
        let predicate = self.eval_node(predicate_id)?;
        let predicate = self.force_value(predicate_id, predicate_span, predicate)?;
        if !matches!(predicate.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: predicate_id,
                    expected: "function",
                    actual: predicate.tag(),
                },
                predicate_span,
            ));
        }

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: list_id,
                        len: list.len(),
                    },
                    list_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };

        self.eval_all_any_elements(
            op,
            id,
            span,
            predicate_id,
            predicate_span,
            predicate,
            list_id,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_all_any_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        op: AllAnyOp,
        predicate: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let predicate_value =
            self.force_value(predicate.id(), predicate.span(), predicate.value())?;
        if !matches!(predicate_value.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: predicate.id(),
                    expected: "function",
                    actual: predicate_value.tag(),
                },
                predicate.span(),
            ));
        }

        let list_value = self.force_value(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };

        self.eval_all_any_elements(
            op,
            id,
            span,
            predicate.id(),
            predicate.span(),
            predicate_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_all_any_elements(
        &mut self,
        op: AllAnyOp,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        predicate_span: Span,
        predicate: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        for element in elements {
            let result = self.apply_lambda_value(
                id,
                span,
                predicate_id,
                predicate,
                predicate_span,
                list_id,
                element,
            )?;
            let result = self.force_value(predicate_id, predicate_span, result)?;
            let actual = result.tag();
            let ValueTag::Bool = actual else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: predicate_id,
                        expected: "bool",
                        actual,
                    },
                    predicate_span,
                ));
            };
            let result = self.expect_bool(predicate_id, result, predicate_span)?;
            if op.short_circuits(result) {
                return Ok(Value::bool(op.short_circuit_value()));
            }
        }

        Ok(Value::bool(op.empty_or_exhausted_value()))
    }

    fn eval_filter_primop(
        &mut self,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };
        if elements.is_empty() {
            return self
                .heap
                .alloc_list(NixList::new(Vec::new()))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
        }

        let predicate_span = self.node(predicate_id)?.span;
        let predicate = self.eval_node(predicate_id)?;
        let predicate = self.force_value(predicate_id, predicate_span, predicate)?;
        if !matches!(predicate.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: predicate_id,
                    expected: "function",
                    actual: predicate.tag(),
                },
                predicate_span,
            ));
        }

        self.eval_filter_elements(
            id,
            span,
            predicate_id,
            predicate_span,
            predicate,
            list_id,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_filter_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        predicate: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let list_value = self.force_value(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };
        if elements.is_empty() {
            return self
                .heap
                .alloc_list(NixList::new(Vec::new()))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
        }

        let predicate_value =
            self.force_value(predicate.id(), predicate.span(), predicate.value())?;
        if !matches!(predicate_value.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: predicate.id(),
                    expected: "function",
                    actual: predicate_value.tag(),
                },
                predicate.span(),
            ));
        }

        self.eval_filter_elements(
            id,
            span,
            predicate.id(),
            predicate.span(),
            predicate_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_filter_elements(
        &mut self,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        predicate_span: Span,
        predicate: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut selected = Vec::new();
        selected.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            let result = self.apply_lambda_value(
                id,
                span,
                predicate_id,
                predicate,
                predicate_span,
                list_id,
                element,
            )?;
            let result = self.force_value(predicate_id, predicate_span, result)?;
            let actual = result.tag();
            let ValueTag::Bool = actual else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: predicate_id,
                        expected: "bool",
                        actual,
                    },
                    predicate_span,
                ));
            };
            if self.expect_bool(predicate_id, result, predicate_span)? {
                selected.push(element);
            }
        }

        self.heap
            .alloc_list(NixList::new(selected))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_map_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };
        if elements.is_empty() {
            return self
                .heap
                .alloc_list(NixList::new(Vec::new()))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
        }

        let function_span = self.node(function_id)?.span;
        let function = self.eval_node(function_id)?;
        let function = self.force_value(function_id, function_span, function)?;
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: function_id,
                    expected: "function",
                    actual: function.tag(),
                },
                function_span,
            ));
        }

        self.alloc_mapped_list(
            id,
            span,
            function_id,
            function_span,
            function,
            list_id,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_map_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let list_value = self.force_value(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };
        if elements.is_empty() {
            return self
                .heap
                .alloc_list(NixList::new(Vec::new()))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
        }

        let function_value = self.force_value(function.id(), function.span(), function.value())?;
        if !matches!(function_value.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: function.id(),
                    expected: "function",
                    actual: function_value.tag(),
                },
                function.span(),
            ));
        }

        self.alloc_mapped_list(
            id,
            span,
            function.id(),
            function.span(),
            function_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn alloc_mapped_list(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut mapped = Vec::new();
        mapped.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            mapped.push(self.alloc_apply_thunk(
                id,
                span,
                function_id,
                function_span,
                function,
                list_id,
                element,
            )?);
        }

        self.heap
            .alloc_list(NixList::new(mapped))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_gen_list_primop(
        &mut self,
        id: IrId,
        span: Span,
        generator_id: IrId,
        length_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let length_span = self.node(length_id)?.span;
        let length_value = self.eval_node(length_id)?;
        let length_value = self.force_value(length_id, length_span, length_value)?;
        let length = self.expect_int(length_id, length_value, length_span)?;
        let length = self.expect_non_negative_list_length(length_id, length, length_span)?;

        let generator_span = self.node(generator_id)?.span;
        let generator = self.eval_node(generator_id)?;
        let generator = self.force_value(generator_id, generator_span, generator)?;
        if !matches!(generator.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: generator_id,
                    expected: "function",
                    actual: generator.tag(),
                },
                generator_span,
            ));
        }

        self.alloc_generated_list(
            id,
            span,
            generator_id,
            generator_span,
            generator,
            length_id,
            length,
        )
    }

    fn eval_gen_list_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        generator: EvalPrimOpArg,
        length: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let length_value = self.force_value(length.id(), length.span(), length.value())?;
        let length_value = self.expect_int(length.id(), length_value, length.span())?;
        let length_value =
            self.expect_non_negative_list_length(length.id(), length_value, length.span())?;

        let generator_value =
            self.force_value(generator.id(), generator.span(), generator.value())?;
        if !matches!(generator_value.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: generator.id(),
                    expected: "function",
                    actual: generator_value.tag(),
                },
                generator.span(),
            ));
        }

        self.alloc_generated_list(
            id,
            span,
            generator.id(),
            generator.span(),
            generator_value,
            length.id(),
            length_value,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn alloc_generated_list(
        &mut self,
        id: IrId,
        span: Span,
        generator_id: IrId,
        generator_span: Span,
        generator: Value,
        length_id: IrId,
        length: usize,
    ) -> Result<Value, TreeWalkError> {
        let mut generated = Vec::new();
        generated.try_reserve_exact(length).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id, len: length },
                span,
            )
        })?;
        for index in 0..length {
            let index = i64::try_from(index).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListLengthOverflow {
                        id: length_id,
                        len: length,
                    },
                    span,
                )
            })?;
            generated.push(self.alloc_apply_thunk(
                id,
                span,
                generator_id,
                generator_span,
                generator,
                length_id,
                Value::int(index),
            )?);
        }

        self.heap
            .alloc_list(NixList::new(generated))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn expect_non_negative_list_length(
        &self,
        id: IrId,
        length: i64,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        if length < 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::NegativeListLength { id, length },
                span,
            ));
        }
        usize::try_from(length).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListLengthOverflow {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })
    }

    fn eval_partition_primop(
        &mut self,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let predicate_span = self.node(predicate_id)?.span;
        let predicate = self.eval_node(predicate_id)?;
        let predicate = self.force_value(predicate_id, predicate_span, predicate)?;
        if !matches!(predicate.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: predicate_id,
                    expected: "function",
                    actual: predicate.tag(),
                },
                predicate_span,
            ));
        }

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };

        self.eval_partition_elements(
            id,
            span,
            predicate_id,
            predicate_span,
            predicate,
            list_id,
            list_span,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_partition_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        predicate: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let predicate_value =
            self.force_value(predicate.id(), predicate.span(), predicate.value())?;
        if !matches!(predicate_value.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: predicate.id(),
                    expected: "function",
                    actual: predicate_value.tag(),
                },
                predicate.span(),
            ));
        }

        let list_value = self.force_value(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };

        self.eval_partition_elements(
            id,
            span,
            predicate.id(),
            predicate.span(),
            predicate_value,
            list.id(),
            list.span(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_partition_elements(
        &mut self,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        predicate_span: Span,
        predicate: Value,
        list_id: IrId,
        list_span: Span,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut right = Vec::new();
        right.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        let mut wrong = Vec::new();
        wrong.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            let element = self.force_value(list_id, list_span, element)?;
            let result = self.apply_lambda_value(
                id,
                span,
                predicate_id,
                predicate,
                predicate_span,
                list_id,
                element,
            )?;
            let result = self.force_value(predicate_id, predicate_span, result)?;
            let actual = result.tag();
            let ValueTag::Bool = actual else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: predicate_id,
                        expected: "bool",
                        actual,
                    },
                    predicate_span,
                ));
            };
            if self.expect_bool(predicate_id, result, predicate_span)? {
                right.push(element);
            } else {
                wrong.push(element);
            }
        }

        let right = self
            .heap
            .alloc_list(NixList::new(right))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let wrong = self
            .heap
            .alloc_list(NixList::new(wrong))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let right_key = self.intern_builtin_attr_symbol(id, b"right", span)?;
        let wrong_key = self.intern_builtin_attr_symbol(id, b"wrong", span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(2).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len: 2 }, span)
        })?;
        entries.push(AttrEntry::new(right_key, right));
        entries.push(AttrEntry::new(wrong_key, wrong));
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_concat_map_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let function_span = self.node(function_id)?.span;
        let function = self.eval_node(function_id)?;
        let function = self.force_value(function_id, function_span, function)?;
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: function_id,
                    expected: "function",
                    actual: function.tag(),
                },
                function_span,
            ));
        }

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };

        self.eval_concat_map_elements(
            id,
            span,
            function_id,
            function_span,
            function,
            list_id,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_concat_map_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let function_value = self.force_value(function.id(), function.span(), function.value())?;
        if !matches!(function_value.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: function.id(),
                    expected: "function",
                    actual: function_value.tag(),
                },
                function.span(),
            ));
        }

        let list_value = self.force_value(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };

        self.eval_concat_map_elements(
            id,
            span,
            function.id(),
            function.span(),
            function_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_concat_map_elements(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut output = Vec::new();
        for element in elements {
            let mapped = self.apply_lambda_value(
                id,
                span,
                function_id,
                function,
                function_span,
                list_id,
                element,
            )?;
            let mapped = self.force_value(function_id, function_span, mapped)?;
            if mapped.tag() != ValueTag::List {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: function_id,
                        expected: "list",
                        actual: mapped.tag(),
                    },
                    function_span,
                ));
            }
            let inner = {
                let list = self.heap.get_list(mapped).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: function_id,
                            source,
                        },
                        function_span,
                    )
                })?;
                Self::clone_list_elements(function_id, function_span, list)?
            };
            let len = output.len().checked_add(inner.len()).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::LengthOverflow {
                            left: output.len(),
                            right: inner.len(),
                        },
                    },
                    span,
                )
            })?;
            output.try_reserve_exact(inner.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::AllocationFailed { len },
                    },
                    span,
                )
            })?;
            output.extend(inner);
        }

        self.heap
            .alloc_list(NixList::new(output))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_group_by_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let function_span = self.node(function_id)?.span;
        let function = self.eval_node(function_id)?;
        let function = self.force_value(function_id, function_span, function)?;
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: function_id,
                    expected: "function",
                    actual: function.tag(),
                },
                function_span,
            ));
        }

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };

        self.eval_group_by_elements(
            id,
            span,
            function_id,
            function_span,
            function,
            list_id,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_group_by_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let function_value = self.force_value(function.id(), function.span(), function.value())?;
        if !matches!(function_value.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: function.id(),
                    expected: "function",
                    actual: function_value.tag(),
                },
                function.span(),
            ));
        }

        let list_value = self.force_value(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };

        self.eval_group_by_elements(
            id,
            span,
            function.id(),
            function.span(),
            function_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_group_by_elements(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut groups: Vec<(Symbol, Vec<Value>)> = Vec::new();
        groups.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: elements.len(),
                    },
                },
                span,
            )
        })?;
        for element in elements {
            let key = self.apply_lambda_value(
                id,
                span,
                function_id,
                function,
                function_span,
                list_id,
                element,
            )?;
            let key = self.force_value(function_id, function_span, key)?;
            if key.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: function_id,
                        expected: "string",
                        actual: key.tag(),
                    },
                    function_span,
                ));
            }
            let key = self.intern_string_value(function_id, key, function_span)?;
            if let Some((_, values)) = groups.iter_mut().find(|(group_key, _)| *group_key == key) {
                let len = values.len().checked_add(1).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::List {
                            id,
                            source: NixListError::LengthOverflow {
                                left: values.len(),
                                right: 1,
                            },
                        },
                        span,
                    )
                })?;
                values.try_reserve_exact(1).map_err(|_| {
                    TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
                })?;
                values.push(element);
            } else {
                let mut values = Vec::new();
                values.try_reserve_exact(1).map_err(|_| {
                    TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len: 1 }, span)
                })?;
                values.push(element);
                groups.push((key, values));
            }
        }

        let mut entries = Vec::new();
        entries.try_reserve_exact(groups.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: groups.len(),
                    },
                },
                span,
            )
        })?;
        for (key, values) in groups {
            let value = self
                .heap
                .alloc_list(NixList::new(values))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
            entries.push(AttrEntry::new(key, value));
        }
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_sort_primop(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            if list.is_empty() {
                return Ok(list_value);
            }
            Self::clone_list_elements(list_id, list_span, list)?
        };

        let comparator_span = self.node(comparator_id)?.span;
        let comparator = self.eval_node(comparator_id)?;
        let comparator = self.force_value(comparator_id, comparator_span, comparator)?;
        self.eval_sort_elements(
            id,
            span,
            comparator_id,
            comparator_span,
            comparator,
            list_id,
            list_span,
            elements,
        )
    }

    fn eval_sort_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        comparator: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let forced_list = self.force_value(list.id(), list.span(), list.value())?;
        if forced_list.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: forced_list.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list(forced_list).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            if list_value.is_empty() {
                return Ok(forced_list);
            }
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };

        let comparator_value =
            self.force_value(comparator.id(), comparator.span(), comparator.value())?;
        self.eval_sort_elements(
            id,
            span,
            comparator.id(),
            comparator.span(),
            comparator_value,
            list.id(),
            list.span(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_sort_elements(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        list_span: Span,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        if !matches!(comparator.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: comparator_id,
                    expected: "function",
                    actual: comparator.tag(),
                },
                comparator_span,
            ));
        }

        let mut elements = self.force_sort_elements(list_id, list_span, elements)?;
        self.eval_sort_libcxx_stable(
            id,
            span,
            comparator_id,
            comparator_span,
            comparator,
            list_id,
            &mut elements,
        )?;

        self.heap
            .alloc_list(NixList::new(elements))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn force_sort_elements(
        &mut self,
        list_id: IrId,
        list_span: Span,
        elements: Vec<Value>,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let mut forced = Vec::new();
        forced.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: list_id,
                    len: elements.len(),
                },
                list_span,
            )
        })?;
        for element in elements {
            forced.push(self.force_value(list_id, list_span, element)?);
        }
        Ok(forced)
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_sort_libcxx_stable(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        elements: &mut [Value],
    ) -> Result<(), TreeWalkError> {
        const LIBCXX_STABLE_SORT_SWITCH_FOR_POINTERS: usize = 128;

        match elements.len() {
            0 | 1 => Ok(()),
            2 => {
                if self.eval_sort_comparator(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    elements[1],
                    elements[0],
                )? {
                    elements.swap(0, 1);
                }
                Ok(())
            }
            len if len <= LIBCXX_STABLE_SORT_SWITCH_FOR_POINTERS => self.eval_sort_insertion(
                id,
                span,
                comparator_id,
                comparator_span,
                comparator,
                list_id,
                elements,
            ),
            len => {
                let middle = len / 2;
                let left = self.eval_sort_libcxx_stable_move(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &mut elements[..middle],
                )?;
                let right = self.eval_sort_libcxx_stable_move(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &mut elements[middle..],
                )?;
                self.eval_sort_merge(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &left,
                    &right,
                    elements,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_sort_libcxx_stable_move(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        elements: &mut [Value],
    ) -> Result<Vec<Value>, TreeWalkError> {
        match elements.len() {
            0 => Ok(Vec::new()),
            1 => {
                let mut sorted = Self::sort_vec_with_capacity(id, span, 1)?;
                sorted.push(elements[0]);
                Ok(sorted)
            }
            2 => {
                let mut sorted = Self::sort_vec_with_capacity(id, span, 2)?;
                if self.eval_sort_comparator(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    elements[1],
                    elements[0],
                )? {
                    sorted.push(elements[1]);
                    sorted.push(elements[0]);
                } else {
                    sorted.push(elements[0]);
                    sorted.push(elements[1]);
                }
                Ok(sorted)
            }
            len if len <= 8 => self.eval_sort_insertion_moved(
                id,
                span,
                comparator_id,
                comparator_span,
                comparator,
                list_id,
                elements,
            ),
            len => {
                let middle = len / 2;
                self.eval_sort_libcxx_stable(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &mut elements[..middle],
                )?;
                self.eval_sort_libcxx_stable(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &mut elements[middle..],
                )?;
                let mut merged = Vec::new();
                merged.try_reserve_exact(len).map_err(|_| {
                    TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
                })?;
                self.eval_sort_merge_to_vec(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &elements[..middle],
                    &elements[middle..],
                    &mut merged,
                )?;
                Ok(merged)
            }
        }
    }

    fn sort_vec_with_capacity(
        id: IrId,
        span: Span,
        len: usize,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let mut values = Vec::new();
        values.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        Ok(values)
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_sort_insertion(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        elements: &mut [Value],
    ) -> Result<(), TreeWalkError> {
        for index in 1..elements.len() {
            let candidate = elements[index];
            let mut insert_at = index;
            while insert_at > 0 {
                let previous = elements[insert_at - 1];
                if !self.eval_sort_comparator(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    candidate,
                    previous,
                )? {
                    break;
                }
                elements[insert_at] = previous;
                insert_at -= 1;
            }
            elements[insert_at] = candidate;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_sort_insertion_moved(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        elements: &[Value],
    ) -> Result<Vec<Value>, TreeWalkError> {
        let mut sorted = Vec::new();
        sorted.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements.iter().copied() {
            let mut insert_at = sorted.len();
            while insert_at > 0 {
                let previous = sorted[insert_at - 1];
                if !self.eval_sort_comparator(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    element,
                    previous,
                )? {
                    break;
                }
                insert_at -= 1;
            }
            sorted.insert(insert_at, element);
        }
        Ok(sorted)
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_sort_merge(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        left: &[Value],
        right: &[Value],
        out: &mut [Value],
    ) -> Result<(), TreeWalkError> {
        let mut merged = Vec::new();
        merged.try_reserve_exact(out.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id, len: out.len() },
                span,
            )
        })?;
        self.eval_sort_merge_to_vec(
            id,
            span,
            comparator_id,
            comparator_span,
            comparator,
            list_id,
            left,
            right,
            &mut merged,
        )?;
        out.copy_from_slice(&merged);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_sort_merge_to_vec(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        left: &[Value],
        right: &[Value],
        out: &mut Vec<Value>,
    ) -> Result<(), TreeWalkError> {
        let mut left_index = 0;
        let mut right_index = 0;
        while left_index < left.len() && right_index < right.len() {
            if self.eval_sort_comparator(
                id,
                span,
                comparator_id,
                comparator_span,
                comparator,
                list_id,
                right[right_index],
                left[left_index],
            )? {
                out.push(right[right_index]);
                right_index += 1;
            } else {
                out.push(left[left_index]);
                left_index += 1;
            }
        }
        out.extend_from_slice(&left[left_index..]);
        out.extend_from_slice(&right[right_index..]);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_sort_comparator(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let step = self.apply_lambda_value(
            id,
            span,
            comparator_id,
            comparator,
            comparator_span,
            list_id,
            left,
        )?;
        let result = self.apply_lambda_value(
            id,
            span,
            comparator_id,
            step,
            comparator_span,
            list_id,
            right,
        )?;
        let result = self.force_value(comparator_id, comparator_span, result)?;
        let actual = result.tag();
        let ValueTag::Bool = actual else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: comparator_id,
                    expected: "bool",
                    actual,
                },
                comparator_span,
            ));
        };
        self.expect_bool(comparator_id, result, comparator_span)
    }

    fn eval_foldl_strict_primop(
        &mut self,
        id: IrId,
        span: Span,
        op_id: IrId,
        initial_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let op_span = self.node(op_id)?.span;
        let op = self.eval_node(op_id)?;
        let op = self.force_value(op_id, op_span, op)?;
        if !matches!(op.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: op_id,
                    expected: "function",
                    actual: op.tag(),
                },
                op_span,
            ));
        }

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };

        let initial_span = self.node(initial_id)?.span;
        let mut accumulator = self.eval_node(initial_id)?;
        accumulator = self.force_value(initial_id, initial_span, accumulator)?;
        for element in elements {
            let step =
                self.apply_lambda_value(id, span, op_id, op, op_span, initial_id, accumulator)?;
            let result =
                self.apply_lambda_value(id, span, op_id, step, op_span, list_id, element)?;
            accumulator = self.force_value(op_id, op_span, result)?;
        }

        Ok(accumulator)
    }

    fn eval_function_args_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let entries = match value.tag() {
            ValueTag::Lambda => {
                let lambda = self.heap.clone_lambda(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                self.function_args_entries(id, span, lambda.pattern())?
            }
            ValueTag::Primop => Vec::new(),
            actual => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "function",
                        actual,
                    },
                    argument_span,
                ));
            }
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn function_args_entries(
        &self,
        id: IrId,
        span: Span,
        pattern: IrId,
    ) -> Result<Vec<AttrEntry>, TreeWalkError> {
        let pattern_node = *self.node(pattern)?;
        match pattern_node.kind {
            IrKind::Formal => Ok(Vec::new()),
            IrKind::FormalSet => {
                let IrData::FormalSet { formals, .. } = pattern_node.data else {
                    return Err(self.invalid_payload(pattern, &pattern_node, "formal-set payload"));
                };
                let formal_slice = self.ir.arena.child_slice(formals).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidChildSlice {
                            id: pattern,
                            slice: formals,
                        },
                        pattern_node.span,
                    )
                })?;
                let mut entries = Vec::new();
                entries.try_reserve_exact(formal_slice.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: formal_slice.len(),
                        },
                        span,
                    )
                })?;
                for formal in formal_slice {
                    let formal_node = *self.node(*formal)?;
                    let IrData::Formal { name, default } = formal_node.data else {
                        return Err(self.invalid_payload(*formal, &formal_node, "formal payload"));
                    };
                    if self.symbols.resolve(name).is_none() {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::InvalidSymbol {
                                id: *formal,
                                symbol: name,
                            },
                            formal_node.span,
                        ));
                    }
                    entries.push(AttrEntry::new(name, Value::bool(default.is_some())));
                }
                Ok(entries)
            }
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedLambdaPattern { id, pattern, kind },
                pattern_node.span,
            )),
        }
    }

    fn alloc_static_string(
        &mut self,
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Value, TreeWalkError> {
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.heap
            .alloc_string(NixString::from_bytes(owned))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn alloc_symbol_string(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
    ) -> Result<Value, TreeWalkError> {
        let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, span)
        })?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.heap
            .alloc_string(NixString::from_bytes(owned))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn apply_lambda_value(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        match function.tag() {
            ValueTag::Lambda => {}
            ValueTag::Primop => {
                let argument_span = self.node(argument_id)?.span;
                return self.apply_primop_value(
                    id,
                    span,
                    function_id,
                    function,
                    function_span,
                    EvalPrimOpArg::new(argument_id, argument_span, argument),
                );
            }
            actual => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: function_id,
                        expected: "lambda",
                        actual,
                    },
                    function_span,
                ));
            }
        }
        let lambda = self.heap.clone_lambda(function).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: function_id,
                    source,
                },
                function_span,
            )
        })?;
        let slot_count = self.frame_info(id, lambda.frame(), span)?.slot_count as usize;
        let call_frame = EvalFrame::new(slot_count)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))?;
        let mut call_env = self.clone_env_frames(id, lambda.env(), span)?;
        let call_with_env = self.clone_with_scopes(id, lambda.with_scope_env(), span)?;
        call_env.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::CaptureAllocationFailed {
                        frames: call_env.len() + 1,
                    },
                },
                span,
            )
        })?;
        call_env.push(call_frame);
        let saved_env = std::mem::replace(&mut self.env, call_env);
        let saved_with_scopes = std::mem::replace(&mut self.with_scopes, call_with_env);
        let result = (|| {
            let call_frame = self.env.last().cloned().ok_or_else(|| {
                TreeWalkError::new(TreeWalkErrorKind::MissingEnvironment { id }, span)
            })?;
            self.bind_lambda_argument(
                id,
                lambda.pattern(),
                slot_count,
                &call_frame,
                argument_id,
                argument,
                span,
            )?;
            self.eval_node(lambda.body())
        })();
        self.env = saved_env;
        self.with_scopes = saved_with_scopes;
        result
    }

    fn apply_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let primop = self.heap.clone_primop(function).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: function_id,
                    source,
                },
                function_span,
            )
        })?;
        let Some(builtin) = lookup_builtin_by_symbol(&self.symbols, primop.symbol()) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedPrimOp {
                    id: function_id,
                    symbol: primop.symbol(),
                },
                function_span,
            ));
        };
        let Some(arity) = builtin.first_class_arity() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedBuiltinAttr {
                    id: function_id,
                    symbol: primop.symbol(),
                },
                function_span,
            ));
        };
        let len = primop.args().len().checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListLengthOverflow {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        let mut args = Vec::new();
        args.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        args.extend_from_slice(primop.args());
        args.push(argument);

        if len < arity {
            return self
                .heap
                .alloc_primop(EvalPrimOp::with_args(primop.symbol(), args))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
        }
        if len > arity {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidPrimOpArity {
                    id,
                    symbol: primop.symbol(),
                    expected: arity,
                    actual: len,
                },
                span,
            ));
        }
        apply_builtin(
            self,
            builtin,
            BuiltinCall::new(id, span, primop.symbol()),
            &args,
        )
    }

    fn eval_strict_ternary_primop_direct(
        &mut self,
        call: BuiltinCall,
        primop: StrictTernaryPrimOp,
        first: IrId,
        second: IrId,
        third: IrId,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictTernaryPrimOp::FoldlStrict => {
                self.eval_foldl_strict_primop(call.id, call.span, first, second, third)
            }
            StrictTernaryPrimOp::ReplaceStrings => {
                self.eval_replace_strings_primop(call.id, call.span, first, second, third)
            }
            StrictTernaryPrimOp::Substring => self.eval_substring_primop(first, second, third),
        }
    }

    fn eval_strict_binary_primop_direct(
        &mut self,
        call: BuiltinCall,
        node: &IrNode,
        primop: StrictBinaryPrimOp,
        first: IrId,
        second: IrId,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictBinaryPrimOp::ElemAt => self.eval_elem_at_primop(first, second),
            StrictBinaryPrimOp::LessThan => {
                self.eval_comparison(call.id, node, ComparisonOp::Lt, first, second)
            }
            StrictBinaryPrimOp::HashString => {
                self.eval_hash_string_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::HashFile => {
                self.eval_hash_file_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::Add => {
                self.eval_numeric_binary(call.id, node, BinaryArithmeticOp::Add, first, second)
            }
            StrictBinaryPrimOp::Sub => {
                self.eval_numeric_binary(call.id, node, BinaryArithmeticOp::Sub, first, second)
            }
            StrictBinaryPrimOp::Mul => {
                self.eval_numeric_binary(call.id, node, BinaryArithmeticOp::Mul, first, second)
            }
            StrictBinaryPrimOp::Div => {
                self.eval_numeric_binary(call.id, node, BinaryArithmeticOp::Div, first, second)
            }
            StrictBinaryPrimOp::BitAnd => self.eval_bitwise_primop(BitwiseOp::And, first, second),
            StrictBinaryPrimOp::BitOr => self.eval_bitwise_primop(BitwiseOp::Or, first, second),
            StrictBinaryPrimOp::BitXor => self.eval_bitwise_primop(BitwiseOp::Xor, first, second),
            StrictBinaryPrimOp::CompareVersions => self.eval_compare_versions_primop(first, second),
            StrictBinaryPrimOp::All => {
                self.eval_all_any_primop(AllAnyOp::All, call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::Any => {
                self.eval_all_any_primop(AllAnyOp::Any, call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::Filter => {
                self.eval_filter_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::GenList => {
                self.eval_gen_list_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::Map => self.eval_map_primop(call.id, call.span, first, second),
            StrictBinaryPrimOp::Partition => {
                self.eval_partition_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::ConcatMap => {
                self.eval_concat_map_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::GroupBy => {
                self.eval_group_by_primop(call.id, call.span, first, second)
            }
        }
    }

    fn eval_direct_binary_primop_direct(
        &mut self,
        call: BuiltinCall,
        node: &IrNode,
        primop: DirectBinaryPrimOp,
        first: IrId,
        second: IrId,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            DirectBinaryPrimOp::GetAttr => {
                self.eval_get_attr_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::HasAttr => self.eval_has_attr_primop(first, second),
            DirectBinaryPrimOp::RemoveAttrs => {
                self.eval_remove_attrs_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::IntersectAttrs => {
                self.eval_intersect_attrs_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::CatAttrs => {
                self.eval_cat_attrs_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::Elem => self.eval_elem_primop(call.id, node, first, second),
            DirectBinaryPrimOp::ConcatStringsSep => {
                self.eval_concat_strings_sep_primop(call.id, call.span, first, second)
            }
        }
    }

    fn eval_direct_binary_primop_value(
        &mut self,
        call: BuiltinCall,
        primop: DirectBinaryPrimOp,
        first: EvalPrimOpArg,
        second: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            DirectBinaryPrimOp::GetAttr => {
                let key = self.eval_attr_name_primop_value(first)?;
                self.eval_get_attr_primop_value(call.id, call.span, key, second)
            }
            DirectBinaryPrimOp::HasAttr => {
                let key = self.eval_attr_name_primop_value(first)?;
                self.eval_has_attr_primop_value(key, second)
            }
            DirectBinaryPrimOp::RemoveAttrs => {
                self.eval_remove_attrs_primop_value(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::IntersectAttrs => {
                self.eval_intersect_attrs_primop_value(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::CatAttrs => {
                let key = self.eval_attr_name_primop_value(first)?;
                self.eval_cat_attrs_primop_value(call.id, call.span, key, second)
            }
            DirectBinaryPrimOp::Elem => self.eval_elem_primop_value(call.id, first, second),
            DirectBinaryPrimOp::ConcatStringsSep => {
                self.eval_concat_strings_sep_primop_value(call.id, call.span, first, second)
            }
        }
    }

    fn eval_attr_name_primop_value(
        &mut self,
        argument: EvalPrimOpArg,
    ) -> Result<Symbol, TreeWalkError> {
        let value = self.force_primop_value(argument, "string", ValueTag::String)?;
        self.intern_string_value(argument.id(), value, argument.span())
    }

    fn eval_get_attr_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        key: Symbol,
        attrs: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_primop_value(attrs, "attrs", ValueTag::Attrs)?;
        let selected = {
            let attrs_set = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs.id(),
                        source,
                    },
                    attrs.span(),
                )
            })?;
            attrs_set.get(key)
        };
        selected.ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                span,
            )
        })
    }

    fn eval_has_attr_primop_value(
        &mut self,
        key: Symbol,
        attrs: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_primop_value(attrs, "attrs", ValueTag::Attrs)?;
        let has_attr = {
            let attrs_set = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs.id(),
                        source,
                    },
                    attrs.span(),
                )
            })?;
            attrs_set.contains_key(key)
        };
        Ok(Value::bool(has_attr))
    }

    fn eval_remove_attrs_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs: EvalPrimOpArg,
        names: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_primop_value(attrs, "attrs", ValueTag::Attrs)?;
        let names_value = self.force_primop_value(names, "list", ValueTag::List)?;
        let name_values = {
            let names_list = self.heap.get_list(names_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: names.id(),
                        source,
                    },
                    names.span(),
                )
            })?;
            Self::clone_list_elements(names.id(), names.span(), names_list)?
        };

        let mut remove = Vec::new();
        remove.try_reserve_exact(name_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: names.id(),
                    len: name_values.len(),
                },
                names.span(),
            )
        })?;
        for value in name_values {
            let value = self.force_value(names.id(), names.span(), value)?;
            if value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: names.id(),
                        expected: "string",
                        actual: value.tag(),
                    },
                    names.span(),
                ));
            }
            let key = self.intern_string_value(names.id(), value, names.span())?;
            if !remove.contains(&key) {
                remove.push(key);
            }
        }

        let entries = {
            let attrs_set = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs.id(),
                        source,
                    },
                    attrs.span(),
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs_set.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: attrs_set.len(),
                    },
                    span,
                )
            })?;
            for entry in attrs_set.entries_by_symbol() {
                if !remove.contains(&entry.key) {
                    entries.push(*entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_intersect_attrs_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        left: EvalPrimOpArg,
        right: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let left_value = self.force_primop_value(left, "attrs", ValueTag::Attrs)?;
        let right_value = self.force_primop_value(right, "attrs", ValueTag::Attrs)?;
        let left_keys = {
            let attrs = self.heap.get_attrs(left_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: left.id(),
                        source,
                    },
                    left.span(),
                )
            })?;
            let mut keys = Vec::new();
            keys.try_reserve_exact(attrs.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: left.id(),
                        len: attrs.len(),
                    },
                    left.span(),
                )
            })?;
            keys.extend(attrs.entries_by_symbol().iter().map(|entry| entry.key));
            keys
        };
        let entries = {
            let attrs = self.heap.get_attrs(right_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: right.id(),
                        source,
                    },
                    right.span(),
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: attrs.len(),
                    },
                    span,
                )
            })?;
            for entry in attrs.entries_by_symbol() {
                if left_keys.contains(&entry.key) {
                    entries.push(*entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_cat_attrs_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        key: Symbol,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let list_value = self.force_primop_value(list, "list", ValueTag::List)?;
        let elements = {
            let list_value = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };
        let mut values = Vec::new();
        values.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            let element = self.force_value(list.id(), list.span(), element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: list.id(),
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    list.span(),
                ));
            }
            let selected = {
                let attrs = self.heap.get_attrs(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: list.id(),
                            source,
                        },
                        list.span(),
                    )
                })?;
                attrs.get(key)
            };
            if let Some(value) = selected {
                values.push(value);
            }
        }
        self.heap
            .alloc_list(NixList::new(values))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_elem_primop_value(
        &mut self,
        id: IrId,
        candidate: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let list_value = self.force_primop_value(list, "list", ValueTag::List)?;
        let elements = {
            let list_values = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_values)?
        };
        if elements.is_empty() {
            return Ok(Value::bool(false));
        }

        let node = *self.node(id)?;
        for element in elements {
            if self.values_equal_nested_lazy(
                id,
                &node,
                candidate.id(),
                candidate.span(),
                candidate.value(),
                list.id(),
                list.span(),
                element,
            )? {
                return Ok(Value::bool(true));
            }
        }
        Ok(Value::bool(false))
    }

    fn eval_concat_strings_sep_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        separator: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let separator_value = self.force_primop_value(separator, "string", ValueTag::String)?;
        let (separator_bytes, separator_context) = {
            let separator_string = self.heap.get_string(separator_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: separator.id(),
                        source,
                    },
                    separator.span(),
                )
            })?;
            let bytes = Self::copy_bytes_for_node(
                separator.id(),
                separator.span(),
                separator_string.bytes(),
            )?;
            let context = separator_string
                .context()
                .union(&StringContext::empty())
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: separator.id(),
                            source,
                        },
                        separator.span(),
                    )
                })?;
            (bytes, context)
        };

        let list_value = self.force_primop_value(list, "list", ValueTag::List)?;
        let elements = {
            let list_value = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };
        let result = self.concat_strings_sep_values(
            id,
            span,
            list.id(),
            list.span(),
            &separator_bytes,
            separator_context,
            &elements,
        )?;
        self.heap
            .alloc_string(result)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn force_primop_value(
        &mut self,
        argument: EvalPrimOpArg,
        expected: &'static str,
        tag: ValueTag,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_value(argument.id(), argument.span(), argument.value())?;
        if value.tag() != tag {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument.id(),
                    expected,
                    actual: value.tag(),
                },
                argument.span(),
            ));
        }
        Ok(value)
    }

    fn force_int_primop_value(&mut self, argument: EvalPrimOpArg) -> Result<i64, TreeWalkError> {
        let value = self.force_value(argument.id(), argument.span(), argument.value())?;
        self.expect_int(argument.id(), value, argument.span())
    }

    fn eval_strict_ternary_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        primop: StrictTernaryPrimOp,
        first: EvalPrimOpArg,
        second: EvalPrimOpArg,
        third: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictTernaryPrimOp::FoldlStrict => {
                self.eval_foldl_strict_primop_value(id, span, first, second, third)
            }
            StrictTernaryPrimOp::ReplaceStrings => {
                self.eval_replace_strings_primop_value(id, span, first, second, third)
            }
            StrictTernaryPrimOp::Substring => {
                self.eval_substring_primop_value(first, second, third)
            }
        }
    }

    fn eval_foldl_strict_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        op_arg: EvalPrimOpArg,
        initial_arg: EvalPrimOpArg,
        list_arg: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let op = self.force_value(op_arg.id(), op_arg.span(), op_arg.value())?;
        if !matches!(op.tag(), ValueTag::Lambda | ValueTag::Primop) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: op_arg.id(),
                    expected: "function",
                    actual: op.tag(),
                },
                op_arg.span(),
            ));
        }
        let list_value = self.force_primop_value(list_arg, "list", ValueTag::List)?;
        let elements = {
            let list = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_arg.id(),
                        source,
                    },
                    list_arg.span(),
                )
            })?;
            Self::clone_list_elements(list_arg.id(), list_arg.span(), list)?
        };

        let mut accumulator =
            self.force_value(initial_arg.id(), initial_arg.span(), initial_arg.value())?;
        for element in elements {
            let step = self.apply_lambda_value(
                id,
                span,
                op_arg.id(),
                op,
                op_arg.span(),
                initial_arg.id(),
                accumulator,
            )?;
            let result = self.apply_lambda_value(
                id,
                span,
                op_arg.id(),
                step,
                op_arg.span(),
                list_arg.id(),
                element,
            )?;
            accumulator = self.force_value(op_arg.id(), op_arg.span(), result)?;
        }

        Ok(accumulator)
    }

    fn eval_replace_strings_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        from_arg: EvalPrimOpArg,
        to_arg: EvalPrimOpArg,
        string_arg: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let from_value = self.force_primop_value(from_arg, "list", ValueTag::List)?;
        let from_values = {
            let from = self.heap.get_list(from_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: from_arg.id(),
                        source,
                    },
                    from_arg.span(),
                )
            })?;
            Self::clone_list_elements(from_arg.id(), from_arg.span(), from)?
        };

        let to_value = self.force_primop_value(to_arg, "list", ValueTag::List)?;
        let to_values = {
            let to = self.heap.get_list(to_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: to_arg.id(),
                        source,
                    },
                    to_arg.span(),
                )
            })?;
            Self::clone_list_elements(to_arg.id(), to_arg.span(), to)?
        };

        if from_values.len() != to_values.len() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ReplaceStringsLengthMismatch {
                    id,
                    from_len: from_values.len(),
                    to_len: to_values.len(),
                },
                span,
            ));
        }

        let mut patterns = Vec::new();
        patterns.try_reserve_exact(from_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: from_values.len(),
                },
                span,
            )
        })?;
        for (from, replacement) in from_values.into_iter().zip(to_values) {
            let from = self.force_value(from_arg.id(), from_arg.span(), from)?;
            if from.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: from_arg.id(),
                        expected: "string",
                        actual: from.tag(),
                    },
                    from_arg.span(),
                ));
            }
            let from = {
                let string = self.heap.get_string(from).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: from_arg.id(),
                            source,
                        },
                        from_arg.span(),
                    )
                })?;
                Self::copy_bytes_for_node(from_arg.id(), from_arg.span(), string.bytes())?
            };
            patterns.push(ReplaceStringPattern { from, replacement });
        }

        let string_value = self.force_primop_value(string_arg, "string", ValueTag::String)?;
        let (source, context) = {
            let string = self.heap.get_string(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_arg.id(),
                        source,
                    },
                    string_arg.span(),
                )
            })?;
            let source =
                Self::copy_bytes_for_node(string_arg.id(), string_arg.span(), string.bytes())?;
            let context = string
                .context()
                .union(&StringContext::empty())
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: string_arg.id(),
                            source,
                        },
                        string_arg.span(),
                    )
                })?;
            (source, context)
        };

        let result = self.replace_strings_bytes(
            id,
            span,
            to_arg.id(),
            to_arg.span(),
            &source,
            context,
            &patterns,
        )?;
        self.heap
            .alloc_string(result)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    fn eval_substring_primop_value(
        &mut self,
        start_arg: EvalPrimOpArg,
        len_arg: EvalPrimOpArg,
        string_arg: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let start_offset = self.force_int_primop_value(start_arg)? as u32 as i32;
        if start_offset < 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::NegativeSubstringStart {
                    id: start_arg.id(),
                    start: start_offset.into(),
                },
                start_arg.span(),
            ));
        }

        let len = self.force_int_primop_value(len_arg)? as u32 as usize;
        let value = self.force_value(string_arg.id(), string_arg.span(), string_arg.value())?;
        let string = self.coerce_to_string(string_arg.id(), value, string_arg.span())?;
        let result = {
            let string = self.heap.get_string(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_arg.id(),
                        source,
                    },
                    string_arg.span(),
                )
            })?;
            string
                .substring_preserve_context(start_offset as usize, len)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: string_arg.id(),
                            source,
                        },
                        string_arg.span(),
                    )
                })?
        };
        self.heap.alloc_string(result).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: string_arg.id(),
                    source,
                },
                string_arg.span(),
            )
        })
    }

    fn eval_strict_binary_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
        primop: StrictBinaryPrimOp,
        first: EvalPrimOpArg,
        second: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictBinaryPrimOp::ElemAt => self.eval_elem_at_primop_value(first, second),
            StrictBinaryPrimOp::HashString => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let algorithm =
                    self.eval_hash_algorithm(first.id(), first.span(), left, "hashString")?;
                let string = self.force_value(second.id(), second.span(), second.value())?;
                if string.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: second.id(),
                            expected: "string",
                            actual: string.tag(),
                        },
                        second.span(),
                    ));
                }
                self.eval_hash_string_value(id, span, second.id(), second.span(), string, algorithm)
            }
            StrictBinaryPrimOp::HashFile => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let algorithm =
                    self.eval_hash_algorithm(first.id(), first.span(), left, "hashFile")?;
                let path_value = self.force_value(second.id(), second.span(), second.value())?;
                let path =
                    self.coerce_to_path_bytes(second.id(), second.span(), path_value, "hashFile")?;
                let contents = fs::read(Path::new(OsStr::from_bytes(&path))).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::FileRead {
                            id: second.id(),
                            path: path.clone(),
                            message: source.to_string(),
                        },
                        second.span(),
                    )
                })?;
                let digest = Self::hash_bytes(&contents, algorithm);
                self.alloc_hash_digest(id, span, &digest)
            }
            StrictBinaryPrimOp::CompareVersions => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let left = self.context_free_string_bytes(
                    first.id(),
                    first.span(),
                    left,
                    "compareVersions",
                )?;
                let right = self.force_value(second.id(), second.span(), second.value())?;
                let right = self.context_free_string_bytes(
                    second.id(),
                    second.span(),
                    right,
                    "compareVersions",
                )?;
                Ok(Value::int(compare_version_bytes(&left, &right)))
            }
            StrictBinaryPrimOp::Add
            | StrictBinaryPrimOp::Sub
            | StrictBinaryPrimOp::Mul
            | StrictBinaryPrimOp::Div => {
                let left = self.force_demanded_value(first.id(), first.span(), first.value())?;
                let right =
                    self.force_demanded_value(second.id(), second.span(), second.value())?;
                let left = self.expect_number(first.id(), left, first.span())?;
                let right = self.expect_number(second.id(), right, second.span())?;
                let node = self.node(id)?;
                let op = match primop {
                    StrictBinaryPrimOp::Add => BinaryArithmeticOp::Add,
                    StrictBinaryPrimOp::Sub => BinaryArithmeticOp::Sub,
                    StrictBinaryPrimOp::Mul => BinaryArithmeticOp::Mul,
                    StrictBinaryPrimOp::Div => BinaryArithmeticOp::Div,
                    _ => {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::UnsupportedPrimOp { id, symbol },
                            span,
                        ));
                    }
                };
                self.eval_numeric_values(id, node, op, left, right)
            }
            StrictBinaryPrimOp::BitAnd | StrictBinaryPrimOp::BitOr | StrictBinaryPrimOp::BitXor => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let left = self.expect_int(first.id(), left, first.span())?;
                let right = self.force_value(second.id(), second.span(), second.value())?;
                let right = self.expect_int(second.id(), right, second.span())?;
                let op = match primop {
                    StrictBinaryPrimOp::BitAnd => BitwiseOp::And,
                    StrictBinaryPrimOp::BitOr => BitwiseOp::Or,
                    StrictBinaryPrimOp::BitXor => BitwiseOp::Xor,
                    _ => {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::UnsupportedPrimOp { id, symbol },
                            span,
                        ));
                    }
                };
                Ok(Value::int(op.apply(left, right)))
            }
            StrictBinaryPrimOp::LessThan => {
                let left = self.force_value(first.id(), first.span(), first.value())?;
                let right = self.force_value(second.id(), second.span(), second.value())?;
                let node = *self.node(id)?;
                self.eval_comparison_values(
                    id,
                    &node,
                    ComparisonOp::Lt,
                    first.id(),
                    first.span(),
                    left,
                    second.id(),
                    second.span(),
                    right,
                )
            }
            StrictBinaryPrimOp::All => {
                self.eval_all_any_primop_value(id, span, AllAnyOp::All, first, second)
            }
            StrictBinaryPrimOp::Any => {
                self.eval_all_any_primop_value(id, span, AllAnyOp::Any, first, second)
            }
            StrictBinaryPrimOp::ConcatMap => {
                self.eval_concat_map_primop_value(id, span, first, second)
            }
            StrictBinaryPrimOp::Filter => self.eval_filter_primop_value(id, span, first, second),
            StrictBinaryPrimOp::GenList => self.eval_gen_list_primop_value(id, span, first, second),
            StrictBinaryPrimOp::GroupBy => self.eval_group_by_primop_value(id, span, first, second),
            StrictBinaryPrimOp::Map => self.eval_map_primop_value(id, span, first, second),
            StrictBinaryPrimOp::Partition => {
                self.eval_partition_primop_value(id, span, first, second)
            }
        }
    }

    fn bind_lambda_argument(
        &mut self,
        id: IrId,
        pattern: IrId,
        slot_count: usize,
        frame: &EvalFrame,
        argument_id: IrId,
        argument: Value,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let pattern_node = *self.node(pattern)?;
        match pattern_node.kind {
            IrKind::Formal => {
                let IrData::Formal {
                    name: _,
                    default: None,
                } = pattern_node.data
                else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::UnsupportedLambdaPattern {
                            id,
                            pattern,
                            kind: pattern_node.kind,
                        },
                        pattern_node.span,
                    ));
                };
                if slot_count != 1 {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::LambdaFrameSlotMismatch {
                            id,
                            frame_slots: slot_count,
                            pattern_slots: 1,
                        },
                        span,
                    ));
                }
                frame.set(0, argument).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                })
            }
            IrKind::FormalSet => self.bind_formal_set_argument(
                id,
                pattern,
                &pattern_node,
                slot_count,
                frame,
                argument_id,
                argument,
                span,
            ),
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedLambdaPattern { id, pattern, kind },
                pattern_node.span,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn bind_formal_set_argument(
        &mut self,
        id: IrId,
        pattern: IrId,
        pattern_node: &IrNode,
        slot_count: usize,
        frame: &EvalFrame,
        argument_id: IrId,
        argument: Value,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let IrData::FormalSet {
            formals,
            ellipsis,
            alias,
        } = pattern_node.data
        else {
            return Err(self.invalid_payload(pattern, pattern_node, "formal-set payload"));
        };
        let formal_slice = self.ir.arena.child_slice(formals).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidChildSlice {
                    id: pattern,
                    slice: formals,
                },
                pattern_node.span,
            )
        })?;
        let mut formal_ids = Vec::new();
        formal_ids
            .try_reserve_exact(formal_slice.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: pattern,
                        len: formal_slice.len(),
                    },
                    pattern_node.span,
                )
            })?;
        formal_ids.extend_from_slice(formal_slice);

        let mut names = Vec::new();
        names.try_reserve_exact(formal_ids.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: pattern,
                    len: formal_ids.len(),
                },
                pattern_node.span,
            )
        })?;
        for formal in &formal_ids {
            let formal_node = *self.node(*formal)?;
            let IrData::Formal { name, .. } = formal_node.data else {
                return Err(self.invalid_payload(*formal, &formal_node, "formal payload"));
            };
            if self.ir.symbols.resolve(name).is_none() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id: *formal,
                        symbol: name,
                    },
                    formal_node.span,
                ));
            }
            names.push(name);
        }
        if let Some(alias) = alias {
            if self.ir.symbols.resolve(alias).is_none() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id: pattern,
                        symbol: alias,
                    },
                    pattern_node.span,
                ));
            }
        }
        let alias_slot = alias.filter(|alias| !names.contains(alias));
        let pattern_slots = names.len() + usize::from(alias_slot.is_some());
        if slot_count != pattern_slots {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::LambdaFrameSlotMismatch {
                    id,
                    frame_slots: slot_count,
                    pattern_slots,
                },
                span,
            ));
        }

        let argument_span = self.node(argument_id)?.span;
        let attrs_value = self.force_value(argument_id, argument_span, argument)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                argument_span,
            ));
        }

        if !ellipsis {
            let unexpected = {
                let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs
                    .iter_lexicographic()
                    .find(|entry| !names.contains(&entry.key))
                    .map(|entry| entry.key)
            };
            if let Some(symbol) = unexpected {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnexpectedFormalAttribute { id, symbol },
                    span,
                ));
            }
        }

        for (slot, formal) in formal_ids.into_iter().enumerate() {
            let formal_node = *self.node(formal)?;
            let IrData::Formal { name, default } = formal_node.data else {
                return Err(self.invalid_payload(formal, &formal_node, "formal payload"));
            };
            let selected = {
                let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs.get(name)
            };
            let value = match (selected, default) {
                (Some(value), _) => value,
                (None, Some(default)) => self.eval_lazy_node(default)?,
                (None, None) => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingFormalAttribute { id, symbol: name },
                        span,
                    ));
                }
            };
            frame.set(slot as u32, value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
            })?;
        }

        if alias_slot.is_some() {
            frame
                .set(names.len() as u32, attrs_value)
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                })?;
        }

        Ok(())
    }

    fn eval_attrset(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::AttrSet {
            shape,
            bindings,
            recursive,
            has_dynamic: _,
            frame,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "attrset payload"));
        };
        let binding_range = self.binding_range(id, bindings, node.span)?;
        {
            let shape_keys = self
                .ir
                .shapes
                .get(shape.index())
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidShapeId { id, shape }, node.span)
                })?
                .keys
                .as_ref();
            self.validate_attrset_shape(id, shape, shape_keys, binding_range.clone(), node.span)?;
        }
        let static_bindings = binding_range
            .clone()
            .filter(|binding_index| {
                matches!(
                    self.ir.bindings[*binding_index].key,
                    IrAttrPathSegment::Static(_)
                )
            })
            .count();
        let dynamic_key_env = if recursive {
            Some(self.env.clone())
        } else {
            None
        };
        let frame_values = if recursive {
            let Some(frame) = frame else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::MissingFrameMetadata { id },
                    node.span,
                ));
            };
            let slot_count = self.frame_info(id, frame, node.span)?.slot_count as usize;
            if slot_count != static_bindings {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetFrameSlotMismatch {
                        id,
                        frame_slots: slot_count,
                        bindings: static_bindings,
                    },
                    node.span,
                ));
            }
            Some(EvalFrame::new(slot_count).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
            })?)
        } else {
            None
        };
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(binding_range.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed {
                            entries: binding_range.len(),
                        },
                    },
                    node.span,
                )
            })?;
        if let Some(frame_values) = &frame_values {
            self.env.push(Rc::clone(frame_values));
        }
        let result = (|| {
            if let Some(frame_values) = &frame_values {
                let mut slot = 0u32;
                for binding_index in binding_range.clone() {
                    let binding = self.ir.bindings[binding_index];
                    if matches!(binding.key, IrAttrPathSegment::Static(_)) {
                        let value = self.eval_lazy_node(binding.value)?;
                        frame_values.set(slot, value).map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                        })?;
                        slot += 1;
                    }
                }
            }

            let mut slot = 0u32;
            for binding_index in binding_range {
                let binding = self.ir.bindings[binding_index];
                let key = if matches!(binding.key, IrAttrPathSegment::Dynamic(_)) {
                    if let Some(dynamic_key_env) = &dynamic_key_env {
                        let saved_env = std::mem::replace(&mut self.env, dynamic_key_env.clone());
                        let result = self.eval_attr_name(
                            id,
                            binding.key,
                            DynamicAttrNullPolicy::SkipNull,
                            node.span,
                        );
                        self.env = saved_env;
                        result?
                    } else {
                        self.eval_attr_name(
                            id,
                            binding.key,
                            DynamicAttrNullPolicy::SkipNull,
                            node.span,
                        )?
                    }
                } else {
                    self.eval_attr_name(
                        id,
                        binding.key,
                        DynamicAttrNullPolicy::SkipNull,
                        node.span,
                    )?
                };
                let Some(key) = key else {
                    continue;
                };
                let value = if let Some(frame_values) = &frame_values {
                    if matches!(binding.key, IrAttrPathSegment::Static(_)) {
                        let value = frame_values.get(slot).map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                        })?;
                        slot += 1;
                        value
                    } else {
                        self.eval_lazy_node(binding.value)?
                    }
                } else {
                    self.eval_lazy_node(binding.value)?
                };
                entries.push(AttrEntry::new(key, value));
            }
            Ok(entries)
        })();
        if recursive {
            let _ = self.env.pop();
        }
        let entries = result?;

        let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, node.span)
        })?;
        self.heap
            .alloc_attrs(shape.as_u32(), attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_select(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Select {
            receiver,
            path: path_id,
            default,
            ..
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "select payload"));
        };
        if let Some(value) =
            self.eval_builtin_static_select(id, node, receiver, path_id, default)?
        {
            return Ok(value);
        }
        let segments = self.attr_path_len(id, path_id, node.span)?;
        let mut current = self.eval_node(receiver)?;
        if segments == 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedAttrPath {
                    id,
                    path: path_id,
                    segments,
                    has_dynamic: false,
                },
                node.span,
            ));
        }

        for index in 0..segments {
            let segment = self.attr_path_segment(id, path_id, index, node.span)?;
            let key = self
                .eval_attr_name(id, segment, DynamicAttrNullPolicy::RejectNull, node.span)?
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: ValueTag::Null,
                        },
                        node.span,
                    )
                })?;
            if current.tag() != ValueTag::Attrs {
                return match default {
                    Some(default) => self.eval_node(default),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "attrs",
                            actual: current.tag(),
                        },
                        node.span,
                    )),
                };
            }
            let selected = {
                let attrs = self.heap.get_attrs(current).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                })?;
                attrs.get(key)
            };
            let Some(value) = selected else {
                return match default {
                    Some(default) => self.eval_node(default),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                        node.span,
                    )),
                };
            };
            if index + 1 == segments {
                return Ok(value);
            }
            current = self.force_value(id, node.span, value)?;
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::UnsupportedAttrPath {
                id,
                path: path_id,
                segments,
                has_dynamic: false,
            },
            node.span,
        ))
    }

    fn eval_builtin_static_select(
        &mut self,
        id: IrId,
        node: &IrNode,
        receiver: IrId,
        path_id: IrAttrPathId,
        default: Option<IrId>,
    ) -> Result<Option<Value>, TreeWalkError> {
        let receiver_node = self.node(receiver)?;
        let IrData::Symbol(receiver_symbol) = receiver_node.data else {
            return Ok(None);
        };
        if receiver_node.kind != IrKind::GlobalVar
            || self.symbols.resolve(receiver_symbol) != Some(b"builtins")
        {
            return Ok(None);
        }

        let path = self.attr_path(id, path_id, node.span)?;
        let Some(IrAttrPathSegment::Static(symbol)) = path.first() else {
            return Ok(None);
        };
        let name = self.symbols.resolve(*symbol).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol {
                    id,
                    symbol: *symbol,
                },
                node.span,
            )
        })?;
        let Some(builtin) = lookup_builtin_by_name(name) else {
            return match default {
                Some(default) => self.eval_node(default).map(Some),
                None => Err(TreeWalkError::new(
                    TreeWalkErrorKind::MissingAttribute {
                        id,
                        symbol: *symbol,
                    },
                    node.span,
                )),
            };
        };
        if !builtin_is_available(self, builtin) {
            return match default {
                Some(default) => self.eval_node(default).map(Some),
                None => Err(TreeWalkError::new(
                    TreeWalkErrorKind::MissingAttribute {
                        id,
                        symbol: *symbol,
                    },
                    node.span,
                )),
            };
        }
        if path.len() == 1 {
            return select_builtin(self, builtin, id, node.span, *symbol).map(Some);
        }

        match default {
            Some(default) => self.eval_node(default).map(Some),
            None => {
                let value = select_builtin(self, builtin, id, node.span, *symbol)?;
                Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id,
                        expected: "attrs",
                        actual: value.tag(),
                    },
                    node.span,
                ))
            }
        }
    }

    fn eval_has_attr(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::HasAttr {
            receiver,
            path: path_id,
            ..
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "has-attr payload"));
        };
        if let Some(value) = self.eval_builtin_static_has_attr(id, node, receiver, path_id)? {
            return Ok(value);
        }
        let segments = self.attr_path_len(id, path_id, node.span)?;
        let mut current = self.eval_node(receiver)?;
        if segments == 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedAttrPath {
                    id,
                    path: path_id,
                    segments,
                    has_dynamic: false,
                },
                node.span,
            ));
        }

        for index in 0..segments {
            let segment = self.attr_path_segment(id, path_id, index, node.span)?;
            let key = self
                .eval_attr_name(id, segment, DynamicAttrNullPolicy::RejectNull, node.span)?
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: ValueTag::Null,
                        },
                        node.span,
                    )
                })?;
            if current.tag() != ValueTag::Attrs {
                return Ok(Value::bool(false));
            }
            let selected = {
                let attrs = self.heap.get_attrs(current).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                })?;
                attrs.get(key)
            };
            let Some(value) = selected else {
                return Ok(Value::bool(false));
            };
            if index + 1 == segments {
                return Ok(Value::bool(true));
            }
            current = self.force_value(id, node.span, value)?;
        }

        Ok(Value::bool(false))
    }

    fn eval_builtin_static_has_attr(
        &mut self,
        id: IrId,
        node: &IrNode,
        receiver: IrId,
        path_id: IrAttrPathId,
    ) -> Result<Option<Value>, TreeWalkError> {
        let receiver_node = self.node(receiver)?;
        let IrData::Symbol(receiver_symbol) = receiver_node.data else {
            return Ok(None);
        };
        if receiver_node.kind != IrKind::GlobalVar
            || self.symbols.resolve(receiver_symbol) != Some(b"builtins")
        {
            return Ok(None);
        }

        let path = self.attr_path(id, path_id, node.span)?;
        let Some(IrAttrPathSegment::Static(symbol)) = path.first() else {
            return Ok(None);
        };
        let name = self.symbols.resolve(*symbol).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol {
                    id,
                    symbol: *symbol,
                },
                node.span,
            )
        })?;
        Ok(Some(Value::bool(
            path.len() == 1
                && lookup_builtin_by_name(name)
                    .is_some_and(|builtin| builtin_is_available(self, builtin)),
        )))
    }

    fn eval_add(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let forced_break_left = self.consume_suspended_lazy_identity_thunk(lhs, lhs_span, left)?;
        let left = if forced_break_left {
            self.force_value(lhs, lhs_span, left)?
        } else {
            left
        };
        match left.tag() {
            ValueTag::Int | ValueTag::Float if !forced_break_left => {
                let rhs_span = self.node(rhs)?.span;
                let right = self.eval_node(rhs)?;
                let left = self.expect_number(lhs, left, lhs_span)?;
                let right = self.expect_number(rhs, right, rhs_span)?;
                self.eval_numeric_values(id, node, BinaryArithmeticOp::Add, left, right)
            }
            ValueTag::String => {
                let rhs_span = self.node(rhs)?.span;
                let right = self.eval_node(rhs)?;
                let right = self.force_demanded_value(rhs, rhs_span, right)?;
                if right.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: rhs,
                            expected: "string",
                            actual: right.tag(),
                        },
                        rhs_span,
                    ));
                }
                self.concat_strings(id, node, left, right)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "number or string",
                    actual,
                },
                lhs_span,
            )),
        }
    }

    fn eval_equality(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
        invert: bool,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_demanded_value(lhs, lhs_span, left)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        let equal = self.values_equal(id, node, left, right, EqualityContext::Direct)?;
        Ok(Value::bool(if invert { !equal } else { equal }))
    }

    fn values_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        _context: EqualityContext,
    ) -> Result<bool, TreeWalkError> {
        match (left.tag(), right.tag()) {
            (ValueTag::Int, ValueTag::Int) => {
                Ok((left.payload_bits() as i64) == (right.payload_bits() as i64))
            }
            (ValueTag::Float, ValueTag::Float) => {
                Ok(f64::from_bits(left.payload_bits()) == f64::from_bits(right.payload_bits()))
            }
            (ValueTag::Int, ValueTag::Float) => {
                Ok((left.payload_bits() as i64) as f64 == f64::from_bits(right.payload_bits()))
            }
            (ValueTag::Float, ValueTag::Int) => {
                Ok(f64::from_bits(left.payload_bits()) == (right.payload_bits() as i64) as f64)
            }
            (ValueTag::Bool, ValueTag::Bool) => Ok(left.payload_bits() == right.payload_bits()),
            (ValueTag::Null, ValueTag::Null) => Ok(true),
            (ValueTag::String, ValueTag::String) => self.strings_equal(id, node, left, right),
            (ValueTag::Path, ValueTag::Path) => self.paths_equal(id, node, left, right),
            (ValueTag::List, ValueTag::List) => self.lists_equal(id, node, left, right),
            (ValueTag::Attrs, ValueTag::Attrs) => self.attrsets_equal(id, node, left, right),
            (ValueTag::Lambda | ValueTag::Primop, ValueTag::Lambda | ValueTag::Primop) => Ok(false),
            (left_tag, right_tag) if left_tag == right_tag => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedEqualityType {
                    id,
                    left: left_tag,
                    right: right_tag,
                },
                node.span,
            )),
            _ => Ok(false),
        }
    }

    fn values_equal_nested_lazy(
        &mut self,
        id: IrId,
        node: &IrNode,
        left_id: IrId,
        left_span: Span,
        left: Value,
        right_id: IrId,
        right_span: Span,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_identity = self.nested_identity_value(id, node.span, left)?;
        let right_identity = self.nested_identity_value(id, node.span, right)?;
        let shared_heap_identity =
            left_identity.raw_eq(right_identity) && left_identity.tag().is_heap();
        if shared_heap_identity && left_identity.tag() != ValueTag::Thunk {
            return Ok(true);
        }

        let left = self.force_value(left_id, left_span, left_identity)?;
        let right = self.force_value(right_id, right_span, right_identity)?;
        if shared_heap_identity
            && left.raw_eq(right)
            && left.tag().is_heap()
            && left.tag() != ValueTag::Thunk
        {
            return Ok(true);
        }
        if shared_heap_identity
            && left.tag() == ValueTag::Float
            && right.tag() == ValueTag::Float
            && f64::from_bits(left.payload_bits()).is_nan()
            && f64::from_bits(right.payload_bits()).is_nan()
        {
            return Ok(true);
        }
        self.values_equal(id, node, left, right, EqualityContext::Nested)
    }

    fn nested_identity_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::Thunk {
            return Ok(value);
        }
        let thunk = self
            .heap
            .clone_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let Some(body) = thunk.body() else {
            return Ok(value);
        };
        let body_node = *self.node(body)?;
        if !matches!(
            body_node.kind,
            IrKind::LocalVar | IrKind::UpvalVar | IrKind::ThunkAlloc
        ) {
            return Ok(value);
        }

        let Some(env) = thunk.env() else {
            return Ok(value);
        };
        let Some(with_env) = thunk.with_scope_env() else {
            return Ok(value);
        };
        let thunk_env = self.clone_env_frames(id, env, span)?;
        let thunk_with_env = self.clone_with_scopes(id, with_env, span)?;
        let saved_env = std::mem::replace(&mut self.env, thunk_env);
        let saved_with_scopes = std::mem::replace(&mut self.with_scopes, thunk_with_env);
        let result = self.eval_nested_equality_operand(body);
        self.env = saved_env;
        self.with_scopes = saved_with_scopes;
        result
    }

    fn strings_equal(
        &self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left = self.heap.get_string(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_string(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(left.bytes() == right.bytes())
    }

    fn paths_equal(
        &self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left = self.heap.get_path(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_path(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(left.bytes() == right.bytes())
    }

    fn lists_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        if left_elements.len() != right_elements.len() {
            return Ok(false);
        }

        for (left, right) in left_elements.into_iter().zip(right_elements) {
            if !self
                .values_equal_nested_lazy(id, node, id, node.span, left, id, node.span, right)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn attrsets_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_entries = {
            let attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        let right_entries = {
            let attrs = self.heap.get_attrs(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        if left_entries.len() != right_entries.len() {
            return Ok(false);
        }

        for (left, right) in left_entries.iter().zip(&right_entries) {
            if left.key != right.key {
                return Ok(false);
            }
        }
        for (left, right) in left_entries.into_iter().zip(right_entries) {
            if !self.values_equal_nested_lazy(
                id,
                node,
                id,
                node.span,
                left.value,
                id,
                node.span,
                right.value,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn eval_numeric_negation(
        &mut self,
        id: IrId,
        node: &IrNode,
        operand: IrId,
    ) -> Result<Value, TreeWalkError> {
        match self.eval_number_node(operand)? {
            Number::Int(value) => value.checked_neg().map(Value::int).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ArithmeticOverflow {
                        id,
                        op: ArithmeticOp::Neg,
                    },
                    node.span,
                )
            }),
            Number::Float(value) => Ok(Value::float(-value)),
        }
    }

    fn eval_numeric_binary(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_demanded_value(lhs, lhs_span, left)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        let left = self.expect_number(lhs, left, lhs_span)?;
        let right = self.expect_number(rhs, right, rhs_span)?;
        self.eval_numeric_values(id, node, op, left, right)
    }

    fn eval_bitwise_primop(
        &mut self,
        op: BitwiseOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left = self.eval_int_node(lhs)?;
        let right = self.eval_int_node(rhs)?;

        Ok(Value::int(op.apply(left, right)))
    }

    fn eval_numeric_values(
        &self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: Number,
        right: Number,
    ) -> Result<Value, TreeWalkError> {
        match (left, right) {
            (Number::Int(left), Number::Int(right)) => {
                self.eval_integer_binary(id, node, op, left, right)
            }
            (left, right) => {
                self.eval_float_binary(id, node, op, left.to_float(), right.to_float())
            }
        }
    }

    fn concat_strings(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let concatenated = {
            let left = self.heap.get_string(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            let right = self.heap.get_string(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            left.concat(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, node.span)
            })?
        };
        self.heap
            .alloc_string(concatenated)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_list_concat(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_demanded_value(lhs, lhs_span, left)?;
        if left.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "list",
                    actual: left.tag(),
                },
                lhs_span,
            ));
        }

        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        if right.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: rhs,
                    expected: "list",
                    actual: right.tag(),
                },
                rhs_span,
            ));
        }

        self.concat_lists(id, node, left, right)
    }

    fn eval_attr_update(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        if left.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "attrs",
                    actual: left.tag(),
                },
                lhs_span,
            ));
        }
        let left_entries = {
            let attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, lhs_span)
            })?;
            Self::clone_attr_entries(id, lhs_span, attrs)?
        };

        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        if right.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: rhs,
                    expected: "attrs",
                    actual: right.tag(),
                },
                rhs_span,
            ));
        }
        let right_entries = {
            let attrs = self.heap.get_attrs(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, rhs_span)
            })?;
            Self::clone_attr_entries(id, rhs_span, attrs)?
        };

        let capacity = left_entries
            .len()
            .checked_add(right_entries.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::TooManyEntries { len: usize::MAX },
                    },
                    node.span,
                )
            })?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: capacity },
                },
                node.span,
            )
        })?;
        for entry in left_entries {
            if !right_entries.iter().any(|right| right.key == entry.key) {
                entries.push(entry);
            }
        }
        entries.extend(right_entries);

        let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, node.span)
        })?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn concat_lists(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let concatenated = {
            let left = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            let right = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            left.concat(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::List { id, source }, node.span)
            })?
        };
        self.heap
            .alloc_list(concatenated)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    fn eval_comparison(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        self.eval_comparison_values(id, node, op, lhs, lhs_span, left, rhs, rhs_span, right)
    }

    fn eval_comparison_values(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        lhs: IrId,
        lhs_span: Span,
        left: Value,
        rhs: IrId,
        rhs_span: Span,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        match left.tag() {
            ValueTag::Int | ValueTag::Float => {
                let left = self.expect_number(lhs, left, lhs_span)?;
                let right = self.expect_number(rhs, right, rhs_span)?;
                Ok(Value::bool(compare_numbers(op, left, right)))
            }
            ValueTag::String => {
                if right.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: rhs,
                            expected: "string",
                            actual: right.tag(),
                        },
                        rhs_span,
                    ));
                }
                self.compare_strings(id, node, op, left, right)
            }
            ValueTag::List => {
                if right.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id: rhs,
                            expected: "list",
                            actual: right.tag(),
                        },
                        rhs_span,
                    ));
                }
                self.compare_lists(id, node, op, left, right)
                    .map(Value::bool)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "number, string, or list",
                    actual,
                },
                lhs_span,
            )),
        }
    }

    fn compare_strings(
        &self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let left = self.heap.get_string(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_string(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(Value::bool(op.compare_bytes(left.bytes(), right.bytes())))
    }

    fn compare_lists(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let mut equality_guard = EqualityPairGuard::default();
        self.compare_lists_with_guard(id, node, op, left, right, &mut equality_guard)
    }

    fn compare_lists_with_guard(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        if !equality_guard.enter(left, right) {
            return Ok(op.compare_equal());
        }

        let result =
            self.compare_list_entries_with_guard(id, node, op, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    fn compare_list_entries_with_guard(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };

        for (left, right) in left_elements
            .iter()
            .copied()
            .zip(right_elements.iter().copied())
        {
            let left = self.force_value(id, node.span, left)?;
            let right = self.force_value(id, node.span, right)?;
            if self.values_equal_for_ordering(id, node, left, right, equality_guard)? {
                continue;
            }
            return self.compare_values_for_ordering(id, node, op, left, right, equality_guard);
        }

        Ok(op.compare_lengths(left_elements.len(), right_elements.len()))
    }

    fn compare_values_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        match left.tag() {
            ValueTag::Int | ValueTag::Float => {
                let left = self.expect_number(id, left, node.span)?;
                let right = self.expect_number(id, right, node.span)?;
                Ok(compare_numbers(op, left, right))
            }
            ValueTag::String => {
                if right.tag() != ValueTag::String {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: right.tag(),
                        },
                        node.span,
                    ));
                }
                self.compare_strings(id, node, op, left, right)
                    .and_then(|value| self.expect_bool(id, value, node.span))
            }
            ValueTag::List => {
                if right.tag() != ValueTag::List {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "list",
                            actual: right.tag(),
                        },
                        node.span,
                    ));
                }
                self.compare_lists_with_guard(id, node, op, left, right, equality_guard)
            }
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "number, string, or list",
                    actual,
                },
                node.span,
            )),
        }
    }

    fn values_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        match (left.tag(), right.tag()) {
            (ValueTag::List, ValueTag::List) => {
                self.lists_equal_for_ordering(id, node, left, right, equality_guard)
            }
            (ValueTag::Attrs, ValueTag::Attrs) => {
                self.attrsets_equal_for_ordering(id, node, left, right, equality_guard)
            }
            _ => self.values_equal(id, node, left, right, EqualityContext::Nested),
        }
    }

    fn lists_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        if !equality_guard.enter(left, right) {
            return Ok(true);
        }

        let result = self.list_entries_equal_for_ordering(id, node, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    fn list_entries_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        if left_elements.len() != right_elements.len() {
            return Ok(false);
        }

        for (left, right) in left_elements.into_iter().zip(right_elements) {
            let left = self.force_value(id, node.span, left)?;
            let right = self.force_value(id, node.span, right)?;
            if !self.values_equal_for_ordering(id, node, left, right, equality_guard)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn attrsets_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        if !equality_guard.enter(left, right) {
            return Ok(true);
        }

        let result = self.attrset_entries_equal_for_ordering(id, node, left, right, equality_guard);
        equality_guard.exit(left, right);
        result
    }

    fn attrset_entries_equal_for_ordering(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        equality_guard: &mut EqualityPairGuard,
    ) -> Result<bool, TreeWalkError> {
        let left_entries = {
            let attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        let right_entries = {
            let attrs = self.heap.get_attrs(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        if left_entries.len() != right_entries.len() {
            return Ok(false);
        }

        for (left, right) in left_entries.iter().zip(&right_entries) {
            if left.key != right.key {
                return Ok(false);
            }
        }
        for (left, right) in left_entries.into_iter().zip(right_entries) {
            let left = self.force_value(id, node.span, left.value)?;
            let right = self.force_value(id, node.span, right.value)?;
            if !self.values_equal_for_ordering(id, node, left, right, equality_guard)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn eval_integer_binary(
        &self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: i64,
        right: i64,
    ) -> Result<Value, TreeWalkError> {
        match op {
            BinaryArithmeticOp::Add => Ok(Value::int(left.wrapping_add(right))),
            BinaryArithmeticOp::Sub => Ok(Value::int(left.wrapping_sub(right))),
            BinaryArithmeticOp::Mul => Ok(Value::int(left.wrapping_mul(right))),
            BinaryArithmeticOp::Div => {
                if right == 0 {
                    return Err(self.division_by_zero(id, node));
                }
                left.checked_div(right).map(Value::int).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ArithmeticOverflow {
                            id,
                            op: ArithmeticOp::Div,
                        },
                        node.span,
                    )
                })
            }
        }
    }

    fn eval_float_binary(
        &self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: f64,
        right: f64,
    ) -> Result<Value, TreeWalkError> {
        let value = match op {
            BinaryArithmeticOp::Add => left + right,
            BinaryArithmeticOp::Sub => left - right,
            BinaryArithmeticOp::Mul => left * right,
            BinaryArithmeticOp::Div => {
                if right == 0.0 {
                    return Err(self.division_by_zero(id, node));
                }
                left / right
            }
        };
        Ok(Value::float(value))
    }

    fn division_by_zero(&self, id: IrId, node: &IrNode) -> TreeWalkError {
        TreeWalkError::new(TreeWalkErrorKind::DivisionByZero { id }, node.span)
    }

    fn eval_bool_node(&mut self, id: IrId) -> Result<bool, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        self.expect_bool(id, value, span)
    }

    fn eval_number_node(&mut self, id: IrId) -> Result<Number, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        let value = self.force_demanded_value(id, span, value)?;
        self.expect_number(id, value, span)
    }

    fn eval_int_node(&mut self, id: IrId) -> Result<i64, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_node(id)?;
        self.expect_int(id, value, span)
    }

    fn expect_bool(&self, id: IrId, value: Value, span: Span) -> Result<bool, TreeWalkError> {
        if value.tag() != ValueTag::Bool {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "bool",
                    actual: value.tag(),
                },
                span,
            ));
        }
        match value.payload_bits() {
            0 => Ok(false),
            1 => Ok(true),
            payload => Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidBoolPayload { id, payload },
                span,
            )),
        }
    }

    fn expect_number(&self, id: IrId, value: Value, span: Span) -> Result<Number, TreeWalkError> {
        match value.tag() {
            ValueTag::Int => Ok(Number::Int(value.payload_bits() as i64)),
            ValueTag::Float => Ok(Number::Float(f64::from_bits(value.payload_bits()))),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "number",
                    actual,
                },
                span,
            )),
        }
    }

    fn expect_int(&self, id: IrId, value: Value, span: Span) -> Result<i64, TreeWalkError> {
        if value.tag() != ValueTag::Int {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "int",
                    actual: value.tag(),
                },
                span,
            ));
        }
        Ok(value.payload_bits() as i64)
    }
}

fn base_name_range(bytes: &[u8]) -> (usize, usize) {
    if bytes.is_empty() {
        return (0, 0);
    }
    let mut last = bytes.len() - 1;
    if bytes[last] == b'/' && last > 0 {
        last -= 1;
    }
    let start = bytes[..=last]
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or(0, |index| index + 1);
    (start, last + 1 - start)
}

fn parse_drv_name_split(bytes: &[u8]) -> (usize, usize) {
    if let Some(dash) = bytes
        .windows(2)
        .position(|pair| pair[0] == b'-' && !pair[1].is_ascii_alphabetic())
    {
        (dash, dash + 1)
    } else {
        (bytes.len(), bytes.len())
    }
}

#[derive(Clone, Debug)]
struct SplitVersionRanges<'a> {
    bytes: &'a [u8],
    next: usize,
}

impl<'a> SplitVersionRanges<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, next: 0 }
    }
}

impl Iterator for SplitVersionRanges<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        while self
            .bytes
            .get(self.next)
            .is_some_and(|byte| matches!(*byte, b'.' | b'-'))
        {
            self.next += 1;
        }
        let start = self.next;
        let first = *self.bytes.get(start)?;
        let digit = first.is_ascii_digit();
        self.next += 1;
        while self
            .bytes
            .get(self.next)
            .is_some_and(|byte| !matches!(*byte, b'.' | b'-') && byte.is_ascii_digit() == digit)
        {
            self.next += 1;
        }
        Some((start, self.next))
    }
}

fn compare_version_bytes(left: &[u8], right: &[u8]) -> i64 {
    let mut left_ranges = SplitVersionRanges::new(left);
    let mut right_ranges = SplitVersionRanges::new(right);
    loop {
        let left_range = left_ranges.next();
        let right_range = right_ranges.next();
        let (Some((left_start, left_end)), Some((right_start, right_end))) =
            (left_range, right_range)
        else {
            return match (left_range, right_range) {
                (None, None) => 0,
                (Some((left_start, left_end)), None) => {
                    compare_version_components(&left[left_start..left_end], b"")
                }
                (None, Some((right_start, right_end))) => {
                    compare_version_components(b"", &right[right_start..right_end])
                }
                (Some(_), Some(_)) => unreachable!("both ranges were matched above"),
            };
        };
        let ordering =
            compare_version_components(&left[left_start..left_end], &right[right_start..right_end]);
        if ordering != 0 {
            return ordering;
        }
    }
}

fn compare_version_components(left: &[u8], right: &[u8]) -> i64 {
    if left == right {
        return 0;
    }
    if left == b"pre" {
        return -1;
    }
    if right == b"pre" {
        return 1;
    }
    let left_digit = left.first().is_some_and(u8::is_ascii_digit);
    let right_digit = right.first().is_some_and(u8::is_ascii_digit);
    match (left_digit, right_digit) {
        (true, true) => compare_version_numbers(left, right),
        (true, false) => 1,
        (false, true) => -1,
        (false, false) => match left.cmp(right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        },
    }
}

fn compare_version_numbers(left: &[u8], right: &[u8]) -> i64 {
    let left = trim_version_leading_zeroes(left);
    let right = trim_version_leading_zeroes(right);
    match left.len().cmp(&right.len()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => match left.cmp(right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        },
    }
}

fn trim_version_leading_zeroes(bytes: &[u8]) -> &[u8] {
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != b'0')
        .unwrap_or(bytes.len());
    &bytes[first_non_zero..]
}

fn dir_name_range(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    if bytes[bytes.len() - 1] == b'/' {
        let mut end = bytes.len();
        while end > 1 && bytes[end - 1] == b'/' && bytes[..end - 1].iter().any(|byte| *byte != b'/')
        {
            end -= 1;
        }
        return Some((0, end));
    }
    let slash = bytes.iter().rposition(|byte| *byte == b'/')?;
    let mut end = slash + 1;
    while end > 1 && bytes[end - 1] == b'/' && bytes[..end].iter().any(|byte| *byte != b'/') {
        end -= 1;
    }
    Some((0, end))
}

fn context_free_dot_string(id: IrId, span: Span) -> Result<NixString, TreeWalkError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(1).map_err(|_| {
        TreeWalkError::new(
            TreeWalkErrorKind::String {
                id,
                source: NixStringError::ByteAllocationFailed { len: 1 },
            },
            span,
        )
    })?;
    bytes.push(b'.');
    Ok(NixString::from_bytes(bytes))
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Number {
    Int(i64),
    Float(f64),
}

#[derive(Debug)]
struct ReflectedContextGroup {
    path: Vec<u8>,
    path_flag: bool,
    all_outputs: bool,
    outputs: Vec<Vec<u8>>,
}

impl ReflectedContextGroup {
    fn new(path: Vec<u8>) -> Self {
        Self {
            path,
            path_flag: false,
            all_outputs: false,
            outputs: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DynamicAttrNullPolicy {
    SkipNull,
    RejectNull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EqualityContext {
    Direct,
    Nested,
}

#[derive(Debug)]
struct ReplaceStringPattern {
    from: Vec<u8>,
    replacement: Value,
}

#[derive(Debug)]
struct ReplaceStringReplacement {
    bytes: Vec<u8>,
    context: StringContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HashStringAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashStringAlgorithm {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"md5" => Some(Self::Md5),
            b"sha1" => Some(Self::Sha1),
            b"sha256" => Some(Self::Sha256),
            b"sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn name(self) -> &'static [u8] {
        match self {
            Self::Md5 => b"md5",
            Self::Sha1 => b"sha1",
            Self::Sha256 => b"sha256",
            Self::Sha512 => b"sha512",
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConvertHashFormat {
    Base16,
    Nix32,
    Base64,
    Sri,
}

impl ConvertHashFormat {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"base16" => Some(Self::Base16),
            b"nix32" | b"base32" => Some(Self::Nix32),
            b"base64" => Some(Self::Base64),
            b"sri" => Some(Self::Sri),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConvertHashInputFormat {
    Sri,
    Typed,
}

#[derive(Clone, Copy, Debug)]
struct BuiltinCall {
    id: IrId,
    span: Span,
    symbol: Symbol,
}

impl BuiltinCall {
    const fn new(id: IrId, span: Span, symbol: Symbol) -> Self {
        Self { id, span, symbol }
    }
}

fn builtin_is_available(eval: &TreeWalk<'_>, builtin: BuiltinMetadata) -> bool {
    match builtin.execution() {
        BuiltinExecution::CurrentSystemValue => eval.options.current_system().is_some(),
        BuiltinExecution::CurrentTimeValue => eval.options.current_time().is_some(),
        _ => true,
    }
}

fn select_builtin(
    eval: &mut TreeWalk<'_>,
    builtin: BuiltinMetadata,
    id: IrId,
    span: Span,
    symbol: Symbol,
) -> Result<Value, TreeWalkError> {
    match builtin.execution() {
        BuiltinExecution::TrueValue => Ok(Value::bool(true)),
        BuiltinExecution::FalseValue => Ok(Value::bool(false)),
        BuiltinExecution::NullValue => Ok(Value::null()),
        BuiltinExecution::CurrentSystemValue => {
            let Some(current_system) = eval.options.current_system() else {
                return unsupported_builtin_attr(id, span, symbol);
            };
            let current_system = current_system.to_vec();
            eval.alloc_static_string(id, span, &current_system)
        }
        BuiltinExecution::CurrentTimeValue => {
            let Some(current_time) = eval.options.current_time() else {
                return unsupported_builtin_attr(id, span, symbol);
            };
            Ok(Value::int(current_time))
        }
        BuiltinExecution::StoreDirValue => {
            let store_dir = eval.options.store_dir().to_vec();
            eval.alloc_static_string(id, span, &store_dir)
        }
        BuiltinExecution::NixVersionValue => eval.alloc_static_string(id, span, PINNED_NIX_VERSION),
        BuiltinExecution::LangVersionValue => Ok(Value::int(PINNED_NIX_LANG_VERSION)),
        _ if builtin.first_class_arity().is_some() => eval
            .heap
            .alloc_primop(EvalPrimOp::new(symbol))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)),
        _ => unsupported_builtin_attr(id, span, symbol),
    }
}

fn apply_builtin_direct(
    eval: &mut TreeWalk<'_>,
    builtin: BuiltinMetadata,
    call: BuiltinCall,
    node: &IrNode,
    args: &[IrId],
) -> Result<Value, TreeWalkError> {
    match builtin.execution() {
        BuiltinExecution::StrictUnary { primop, .. } => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let argument_span = eval.node(argument)?.span;
            let value = eval.eval_node(argument)?;
            eval.eval_strict_unary_primop_value(
                call.id,
                call.span,
                primop,
                argument,
                argument_span,
                value,
            )
        }
        BuiltinExecution::LazyUnary => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let argument_span = eval.node(argument)?.span;
            let value = eval.eval_lazy_node(argument)?;
            eval.eval_lazy_identity_value(argument, argument_span, value)
        }
        BuiltinExecution::StrictBinary { primop, .. } => {
            check_builtin_arity(call, 2, args.len())?;
            eval.eval_strict_binary_primop_direct(call, node, primop, args[0], args[1])
        }
        BuiltinExecution::DirectBinary(primop) => {
            check_builtin_arity(call, 2, args.len())?;
            eval.eval_direct_binary_primop_direct(call, node, primop, args[0], args[1])
        }
        BuiltinExecution::DirectTernary(primop) => {
            check_builtin_arity(call, 3, args.len())?;
            eval.eval_strict_ternary_primop_direct(call, primop, args[0], args[1], args[2])
        }
        BuiltinExecution::Sort => {
            check_builtin_arity(call, 2, args.len())?;
            eval.eval_sort_primop(call.id, call.span, args[0], args[1])
        }
        BuiltinExecution::TryEval => {
            check_builtin_arity(call, 1, args.len())?;
            eval.eval_try_eval_direct(call.id, call.span, args[0])
        }
        BuiltinExecution::PathExists => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let argument_span = eval.node(argument)?.span;
            let value = eval.eval_node(argument)?;
            eval.eval_path_exists_primop(argument, argument_span, value)
        }
        BuiltinExecution::ReadDir => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let argument_span = eval.node(argument)?.span;
            let value = eval.eval_node(argument)?;
            eval.eval_read_dir_primop(call.id, call.span, argument, argument_span, value)
        }
        BuiltinExecution::ReadFile => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let argument_span = eval.node(argument)?.span;
            let value = eval.eval_node(argument)?;
            eval.eval_read_file_primop(call.id, call.span, argument, argument_span, value)
        }
        BuiltinExecution::ReadFileType => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let argument_span = eval.node(argument)?.span;
            let value = eval.eval_node(argument)?;
            eval.eval_read_file_type_primop(call.id, call.span, argument, argument_span, value)
        }
        BuiltinExecution::Seq => {
            check_builtin_arity(call, 2, args.len())?;
            eval.eval_seq_primop(args[0], args[1])
        }
        BuiltinExecution::DeepSeq => {
            check_builtin_arity(call, 2, args.len())?;
            eval.eval_deep_seq_primop(args[0], args[1])
        }
        BuiltinExecution::EffectfulUnaryUnsupported => {
            check_builtin_arity(call, 1, args.len())?;
            eval.eval_node(args[0])?;
            unsupported_primop(call)
        }
        _ => unsupported_primop(call),
    }
}

fn apply_builtin(
    eval: &mut TreeWalk<'_>,
    builtin: BuiltinMetadata,
    call: BuiltinCall,
    args: &[EvalPrimOpArg],
) -> Result<Value, TreeWalkError> {
    match builtin.execution() {
        BuiltinExecution::StrictUnary { primop, .. } => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let value = eval.force_value(argument.id(), argument.span(), argument.value())?;
            eval.eval_strict_unary_primop_value(
                call.id,
                call.span,
                primop,
                argument.id(),
                argument.span(),
                value,
            )
        }
        BuiltinExecution::LazyUnary => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            eval.eval_lazy_identity_value(argument.id(), argument.span(), argument.value())
        }
        BuiltinExecution::StrictBinary { primop, .. } => {
            check_builtin_arity(call, 2, args.len())?;
            eval.eval_strict_binary_primop_value(
                call.id,
                call.span,
                call.symbol,
                primop,
                args[0],
                args[1],
            )
        }
        BuiltinExecution::DirectBinary(primop) => {
            check_builtin_arity(call, 2, args.len())?;
            eval.eval_direct_binary_primop_value(call, primop, args[0], args[1])
        }
        BuiltinExecution::DirectTernary(primop) => {
            check_builtin_arity(call, 3, args.len())?;
            eval.eval_strict_ternary_primop_value(
                call.id, call.span, primop, args[0], args[1], args[2],
            )
        }
        BuiltinExecution::Sort => {
            check_builtin_arity(call, 2, args.len())?;
            eval.eval_sort_primop_value(call.id, call.span, args[0], args[1])
        }
        BuiltinExecution::TryEval => {
            check_builtin_arity(call, 1, args.len())?;
            eval.eval_try_eval_value(call.id, call.span, args[0])
        }
        BuiltinExecution::PathExists => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let value = eval.force_value(argument.id(), argument.span(), argument.value())?;
            eval.eval_path_exists_primop(argument.id(), argument.span(), value)
        }
        BuiltinExecution::ReadDir => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let value = eval.force_value(argument.id(), argument.span(), argument.value())?;
            eval.eval_read_dir_primop(call.id, call.span, argument.id(), argument.span(), value)
        }
        BuiltinExecution::ReadFile => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let value = eval.force_value(argument.id(), argument.span(), argument.value())?;
            eval.eval_read_file_primop(call.id, call.span, argument.id(), argument.span(), value)
        }
        BuiltinExecution::ReadFileType => {
            check_builtin_arity(call, 1, args.len())?;
            let argument = args[0];
            let value = eval.force_value(argument.id(), argument.span(), argument.value())?;
            eval.eval_read_file_type_primop(
                call.id,
                call.span,
                argument.id(),
                argument.span(),
                value,
            )
        }
        BuiltinExecution::Seq => {
            check_builtin_arity(call, 2, args.len())?;
            let first = args[0];
            let value = eval.force_value(first.id(), first.span(), first.value())?;
            eval.consume_suspended_lazy_identity_thunk(first.id(), first.span(), value)?;
            Ok(args[1].value())
        }
        BuiltinExecution::DeepSeq => {
            check_builtin_arity(call, 2, args.len())?;
            let first = args[0];
            let value = eval.force_value(first.id(), first.span(), first.value())?;
            if !eval.consume_suspended_lazy_identity_thunk(first.id(), first.span(), value)? {
                let mut visited = Vec::new();
                eval.deep_force_value(first.id(), first.span(), value, &mut visited)?;
            }
            Ok(args[1].value())
        }
        _ => unsupported_primop(call),
    }
}

fn unsupported_primop(call: BuiltinCall) -> Result<Value, TreeWalkError> {
    Err(TreeWalkError::new(
        TreeWalkErrorKind::UnsupportedPrimOp {
            id: call.id,
            symbol: call.symbol,
        },
        call.span,
    ))
}

fn unsupported_builtin_attr(id: IrId, span: Span, symbol: Symbol) -> Result<Value, TreeWalkError> {
    Err(TreeWalkError::new(
        TreeWalkErrorKind::UnsupportedBuiltinAttr { id, symbol },
        span,
    ))
}

fn check_builtin_arity(
    call: BuiltinCall,
    expected: usize,
    actual: usize,
) -> Result<(), TreeWalkError> {
    if actual == expected {
        return Ok(());
    }

    Err(TreeWalkError::new(
        TreeWalkErrorKind::InvalidPrimOpArity {
            id: call.id,
            symbol: call.symbol,
            expected,
            actual,
        },
        call.span,
    ))
}

fn lookup_builtin_by_name(name: &[u8]) -> Option<BuiltinMetadata> {
    builtin_metadata(name)
}

fn lookup_builtin_by_symbol(symbols: &SymbolTable, symbol: Symbol) -> Option<BuiltinMetadata> {
    symbols.resolve(symbol).and_then(lookup_builtin_by_name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThrowAbortOp {
    Throw,
    Abort,
}

#[derive(Debug, Default)]
struct EqualityPairGuard {
    active: Vec<(Value, Value)>,
}

impl EqualityPairGuard {
    fn enter(&mut self, left: Value, right: Value) -> bool {
        if self.active.iter().any(|(active_left, active_right)| {
            (active_left.raw_eq(left) && active_right.raw_eq(right))
                || (active_left.raw_eq(right) && active_right.raw_eq(left))
        }) {
            return false;
        }
        self.active.push((left, right));
        true
    }

    fn exit(&mut self, left: Value, right: Value) {
        let active = self.active.pop();
        debug_assert!(active.is_some_and(|(active_left, active_right)| {
            active_left.raw_eq(left) && active_right.raw_eq(right)
        }));
    }
}

impl Number {
    fn to_float(self) -> f64 {
        match self {
            Self::Int(value) => value as f64,
            Self::Float(value) => value,
        }
    }
}

fn compare_numbers(op: ComparisonOp, left: Number, right: Number) -> bool {
    match (left, right) {
        (Number::Int(left), Number::Int(right)) => op.compare_ints(left, right),
        (left, right) => op.compare_floats(left.to_float(), right.to_float()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BinaryArithmeticOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BitwiseOp {
    And,
    Or,
    Xor,
}

impl BitwiseOp {
    const fn apply(self, left: i64, right: i64) -> i64 {
        match self {
            Self::And => left & right,
            Self::Or => left | right,
            Self::Xor => left ^ right,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllAnyOp {
    All,
    Any,
}

impl AllAnyOp {
    const fn short_circuits(self, value: bool) -> bool {
        match self {
            Self::All => !value,
            Self::Any => value,
        }
    }

    const fn short_circuit_value(self) -> bool {
        match self {
            Self::All => false,
            Self::Any => true,
        }
    }

    const fn empty_or_exhausted_value(self) -> bool {
        match self {
            Self::All => true,
            Self::Any => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComparisonOp {
    Lt,
    Gt,
    Le,
    Ge,
}

impl ComparisonOp {
    const fn compare_ints(self, left: i64, right: i64) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }

    fn compare_floats(self, left: f64, right: f64) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }

    fn compare_bytes(self, left: &[u8], right: &[u8]) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }

    const fn compare_equal(self) -> bool {
        match self {
            Self::Lt | Self::Gt => false,
            Self::Le | Self::Ge => true,
        }
    }

    const fn compare_lengths(self, left: usize, right: usize) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Gt => left > right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
        }
    }
}

/// A numeric arithmetic operator used in tree-walk diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArithmeticOp {
    /// Unary numeric negation.
    Neg,
    /// Binary numeric addition.
    Add,
    /// Binary numeric subtraction.
    Sub,
    /// Binary numeric multiplication.
    Mul,
    /// Binary numeric division.
    Div,
    /// Float-to-integer ceiling.
    Ceil,
    /// Float-to-integer floor.
    Floor,
}

/// A tree-walk evaluation failure with source location.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{kind} at byte span {span:?}")]
pub struct TreeWalkError {
    kind: TreeWalkErrorKind,
    span: Span,
}

impl TreeWalkError {
    /// Creates a tree-walk evaluation error.
    pub const fn new(kind: TreeWalkErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Returns the error category.
    pub fn kind(&self) -> TreeWalkErrorKind {
        self.kind.clone()
    }

    /// Returns the source span associated with this error.
    pub const fn span(&self) -> Span {
        self.span
    }
}

/// The category of a tree-walk evaluation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkErrorKind {
    /// The evaluator was asked to read a missing IR node.
    #[error("invalid IR node id {id:?}")]
    InvalidNodeId {
        /// The missing node id.
        id: IrId,
    },
    /// The node kind and node payload disagreed.
    #[error("invalid payload for {kind:?} node {id:?}; expected {expected}")]
    InvalidPayload {
        /// The malformed node id.
        id: IrId,
        /// The node kind whose payload was malformed.
        kind: IrKind,
        /// The expected payload contract.
        expected: &'static str,
    },
    /// A child-pool slice payload did not resolve through the IR arena.
    #[error("invalid child slice {slice:?} at node {id:?}")]
    InvalidChildSlice {
        /// The node id carrying the invalid child slice.
        id: IrId,
        /// The invalid child slice payload.
        slice: IrChildSlice,
    },
    /// An attribute-path side-table id did not resolve through the IR.
    #[error("invalid attribute path {path:?} at node {id:?}")]
    InvalidAttrPath {
        /// The node id carrying the invalid attribute-path id.
        id: IrId,
        /// The invalid attribute-path id payload.
        path: IrAttrPathId,
    },
    /// A binding-table slice payload did not resolve through the IR.
    #[error("invalid binding slice {slice:?} at node {id:?}")]
    InvalidBindingSlice {
        /// The node id carrying the invalid binding slice.
        id: IrId,
        /// The invalid binding slice payload.
        slice: IrBindingSlice,
    },
    /// An attrset shape id payload did not resolve through the IR.
    #[error("invalid attrset shape {shape:?} at node {id:?}")]
    InvalidShapeId {
        /// The node id carrying the invalid shape id.
        id: IrId,
        /// The invalid shape id payload.
        shape: IrShapeId,
    },
    /// A node that needs a resolver frame referenced none.
    #[error("missing frame metadata at node {id:?}")]
    MissingFrameMetadata {
        /// The malformed node id.
        id: IrId,
    },
    /// A resolver frame id did not resolve through the IR.
    #[error("invalid frame id {frame} at node {id:?}")]
    InvalidFrameId {
        /// The node id carrying the invalid frame id.
        id: IrId,
        /// The invalid frame id payload.
        frame: u32,
    },
    /// A with-chain id did not resolve through the lowered IR.
    #[error("invalid with-chain id {chain} at node {id:?}")]
    InvalidWithChain {
        /// The node id carrying the invalid with-chain id.
        id: IrId,
        /// The invalid with-chain id payload.
        chain: u32,
    },
    /// A with-chain scope did not have a matching active runtime scope.
    #[error("missing active with scope {scope:?} at node {id:?}")]
    MissingWithScope {
        /// The with-variable node id.
        id: IrId,
        /// The lowered scope node id from the with-chain.
        scope: IrId,
    },
    /// A let frame's slot count did not match its binding table.
    #[error("let frame at node {id:?} has {frame_slots} slots for {bindings} bindings")]
    LetFrameSlotMismatch {
        /// The malformed let node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of lowered bindings.
        bindings: usize,
    },
    /// A recursive attrset frame's slot count did not match its binding table.
    #[error(
        "recursive attrset frame at node {id:?} has {frame_slots} slots for {bindings} bindings"
    )]
    AttrSetFrameSlotMismatch {
        /// The malformed attrset node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of lowered bindings.
        bindings: usize,
    },
    /// A lambda frame's slot count did not match the supported pattern.
    #[error(
        "lambda frame at node {id:?} has {frame_slots} slots for {pattern_slots} pattern slots"
    )]
    LambdaFrameSlotMismatch {
        /// The malformed lambda or application node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of slots expected by the supported pattern.
        pattern_slots: usize,
    },
    /// A lambda used a parameter pattern not implemented by this evaluator slice.
    #[error("unsupported lambda pattern {pattern:?} ({kind:?}) at node {id:?}")]
    UnsupportedLambdaPattern {
        /// The application node id.
        id: IrId,
        /// The unsupported pattern node id.
        pattern: IrId,
        /// The unsupported pattern node kind.
        kind: IrKind,
    },
    /// A local variable was evaluated without an active environment frame.
    #[error("missing lexical environment at node {id:?}")]
    MissingEnvironment {
        /// The variable node id.
        id: IrId,
    },
    /// An upvalue depth did not resolve through the active environment stack.
    #[error("upvalue depth {depth} at node {id:?} exceeds {frames} active frames")]
    InvalidUpvalueDepth {
        /// The upvalue node id.
        id: IrId,
        /// The requested parent depth.
        depth: usize,
        /// The number of active frames.
        frames: usize,
    },
    /// A let binding carried an unsupported dynamic key.
    #[error("unsupported let binding key at node {id:?}")]
    UnsupportedLetBindingKey {
        /// The malformed let node id.
        id: IrId,
    },
    /// An attrset shape has a different number of keys than its binding slice.
    #[error(
        "attrset shape {shape:?} at node {id:?} has {shape_keys} keys for {binding_keys} binding keys"
    )]
    AttrSetShapeLengthMismatch {
        /// The attrset node id carrying the mismatched metadata.
        id: IrId,
        /// The shape id carrying the mismatched key table.
        shape: IrShapeId,
        /// The number of keys recorded in the shape table.
        shape_keys: usize,
        /// The number of static keys found in the binding slice.
        binding_keys: usize,
    },
    /// An attrset shape key does not match the corresponding binding key.
    #[error(
        "attrset shape {shape:?} at node {id:?} key {index} is {expected:?}, but binding key is {actual:?}"
    )]
    AttrSetShapeKeyMismatch {
        /// The attrset node id carrying the mismatched metadata.
        id: IrId,
        /// The shape id carrying the mismatched key table.
        shape: IrShapeId,
        /// The mismatched key index.
        index: usize,
        /// The symbol recorded by the shape table.
        expected: Symbol,
        /// The symbol found in the binding slice.
        actual: Symbol,
    },
    /// A symbol payload did not resolve through the IR symbol table.
    #[error("invalid symbol {symbol:?} at node {id:?}")]
    InvalidSymbol {
        /// The node id associated with the missing symbol.
        id: IrId,
        /// The unresolved symbol payload.
        symbol: Symbol,
    },
    /// A runtime-computed attribute name could not be interned.
    #[error("runtime attribute-name interning failed at node {id:?}: {source}")]
    SymbolIntern {
        /// The node id associated with the runtime attribute name.
        id: IrId,
        /// The underlying symbol-table failure.
        source: crate::syntax::AstErrorKind,
    },
    /// A byte buffer for a string literal could not be reserved.
    #[error("failed to reserve {len} string bytes at node {id:?}")]
    ByteAllocationFailed {
        /// The string node id.
        id: IrId,
        /// The requested byte length.
        len: usize,
    },
    /// A path-taking primop received a relative string.
    #[error("path at node {id:?} is not absolute: {path:?}")]
    PathNotAbsolute {
        /// The path-valued node being coerced.
        id: IrId,
        /// The rejected path bytes.
        path: Vec<u8>,
    },
    /// A file-content primop could not read its target path.
    #[error("failed to read file at node {id:?} path {path:?}: {message}")]
    FileRead {
        /// The path-valued node being read.
        id: IrId,
        /// The file path bytes.
        path: Vec<u8>,
        /// The filesystem diagnostic.
        message: String,
    },
    /// A file-content primop read bytes that cannot be represented as a Nix string.
    #[error("file at node {id:?} path {path:?} contains a NUL byte")]
    FileReadContainsNul {
        /// The path-valued node being read.
        id: IrId,
        /// The file path bytes.
        path: Vec<u8>,
    },
    /// A filesystem-stat primop could not inspect its target path.
    #[error("failed to stat path at node {id:?} path {path:?}: {message}")]
    PathStat {
        /// The path-valued node being inspected.
        id: IrId,
        /// The path bytes.
        path: Vec<u8>,
        /// The filesystem diagnostic.
        message: String,
    },
    /// A directory-listing primop could not read its target directory.
    #[error("failed to read directory at node {id:?} path {path:?}: {message}")]
    DirectoryRead {
        /// The path-valued node being listed.
        id: IrId,
        /// The directory path bytes.
        path: Vec<u8>,
        /// The filesystem diagnostic.
        message: String,
    },
    /// A list spine buffer could not be reserved.
    #[error("failed to reserve {len} list elements at node {id:?}")]
    ListAllocationFailed {
        /// The list node id.
        id: IrId,
        /// The requested list length.
        len: usize,
    },
    /// A list length could not fit in the Nix integer type.
    #[error("list length {len} at node {id:?} does not fit in i64")]
    ListLengthOverflow {
        /// The list-valued node whose length overflowed.
        id: IrId,
        /// The overflowing list length.
        len: usize,
    },
    /// A builtin list length argument was negative.
    #[error("negative list length {length} at node {id:?}")]
    NegativeListLength {
        /// The length-valued node whose signed value was invalid.
        id: IrId,
        /// The negative length.
        length: i64,
    },
    /// `replaceStrings` received pattern and replacement lists of different lengths.
    #[error("replaceStrings at node {id:?} received {from_len} patterns but {to_len} replacements")]
    ReplaceStringsLengthMismatch {
        /// The primop node id.
        id: IrId,
        /// The number of pattern strings.
        from_len: usize,
        /// The number of replacement strings.
        to_len: usize,
    },
    /// A list primop received an empty list where it requires an element.
    #[error("{op} received an empty list at node {id:?}")]
    EmptyListPrimOp {
        /// The list-valued node that was empty.
        id: IrId,
        /// The primop that rejected the empty list.
        op: &'static str,
    },
    /// A list primop index was outside the list spine.
    #[error("list index {index} out of bounds for length {len} at node {id:?}")]
    ListIndexOutOfBounds {
        /// The index-valued node that was outside the list.
        id: IrId,
        /// The requested signed index.
        index: i64,
        /// The list spine length.
        len: usize,
    },
    /// A substring start offset was negative or overflowed the builtin offset type.
    #[error("negative substring start {start} at node {id:?}")]
    NegativeSubstringStart {
        /// The start-valued node whose offset was invalid.
        id: IrId,
        /// The effective signed 32-bit start offset.
        start: i64,
    },
    /// The active with-scope stack could not reserve another entry.
    #[error("failed to reserve {scopes} active with scopes at node {id:?}")]
    WithScopeAllocationFailed {
        /// The with-expression node id.
        id: IrId,
        /// The requested number of active with scopes.
        scopes: usize,
    },
    /// A heap-backed value was produced by the non-owning convenience API.
    #[error("heap-backed {tag:?} value at node {id:?} requires an owning evaluation result")]
    HeapValueRequiresOwner {
        /// The root node id that produced the heap value.
        id: IrId,
        /// The heap-backed value tag.
        tag: ValueTag,
    },
    /// The evaluator heap failed while allocating or retrieving a value.
    #[error("heap operation failed at node {id:?}: {source}")]
    Heap {
        /// The node id associated with the heap operation.
        id: IrId,
        /// The underlying heap failure.
        source: EvalHeapError,
    },
    /// Lexical environment access failed.
    #[error("environment operation failed at node {id:?}: {source}")]
    Env {
        /// The node id associated with the environment operation.
        id: IrId,
        /// The underlying environment failure.
        source: EvalEnvError,
    },
    /// Thunk forcing failed.
    #[error("thunk force failed at node {id:?}: {source}")]
    Force {
        /// The node id associated with the force operation.
        id: IrId,
        /// The underlying force failure.
        source: ForceError,
    },
    /// A Nix string operation failed.
    #[error("string operation failed at node {id:?}: {source}")]
    String {
        /// The node id associated with the string operation.
        id: IrId,
        /// The underlying string failure.
        source: NixStringError,
    },
    /// A primop received a context-bearing string where C++ Nix forbids one.
    #[error("{op} does not allow string context at node {id:?}")]
    StringContextNotAllowed {
        /// The node id associated with the rejected string.
        id: IrId,
        /// The primop rejecting the string context.
        op: &'static str,
    },
    /// A context-transforming primop required exactly one string-context element.
    #[error("string context at node {id:?} must have exactly one element, but has {len}")]
    StringContextElementCount {
        /// The string-valued node whose context had the wrong cardinality.
        id: IrId,
        /// The observed context element count.
        len: usize,
    },
    /// A context-transforming primop required a derivation path context.
    #[error("string context path at node {id:?} is not a derivation: {path:?}")]
    StringContextPathNotDerivation {
        /// The string-valued node whose context path was rejected.
        id: IrId,
        /// The rejected context path bytes.
        path: Vec<u8>,
    },
    /// A context-transforming primop rejected a single derivation output context.
    #[error("string context at node {id:?} names derivation output {output:?}")]
    StringContextDerivationOutput {
        /// The string-valued node whose context output was rejected.
        id: IrId,
        /// The rejected output name bytes.
        output: Vec<u8>,
    },
    /// A JSON string failed to parse.
    #[error("JSON parse failed at node {id:?}: {message}")]
    JsonParse {
        /// The string-valued node that was parsed as JSON.
        id: IrId,
        /// The parser diagnostic.
        message: String,
    },
    /// A parsed JSON number did not fit any supported evaluator number shape.
    #[error("unsupported JSON number at node {id:?}")]
    JsonNumberUnsupported {
        /// The string-valued node that produced the unsupported number.
        id: IrId,
    },
    /// A value cannot be represented as JSON.
    #[error("cannot convert {actual:?} at node {id:?} to JSON")]
    JsonUnsupportedValue {
        /// The value node that could not be converted.
        id: IrId,
        /// The unsupported runtime tag.
        actual: ValueTag,
    },
    /// A hash primop received an unsupported algorithm name.
    #[error("unknown hash algorithm at node {id:?}: {algorithm:?}")]
    UnknownHashAlgorithm {
        /// The algorithm string node.
        id: IrId,
        /// The unsupported algorithm bytes.
        algorithm: Vec<u8>,
    },
    /// `builtins.convertHash` received an unsupported output format.
    #[error("unknown hash format at node {id:?}: {format:?}")]
    UnknownHashFormat {
        /// The format string node.
        id: IrId,
        /// The unsupported output format bytes.
        format: Vec<u8>,
    },
    /// `builtins.convertHash` received an untyped hash without `hashAlgo`.
    #[error("hash at node {id:?} does not include an algorithm: {hash:?}")]
    HashAlgorithmRequired {
        /// The convertHash argument node.
        id: IrId,
        /// The hash bytes that need an explicit algorithm.
        hash: Vec<u8>,
    },
    /// `builtins.convertHash` received a typed hash that disagreed with `hashAlgo`.
    #[error("hash at node {id:?} does not match expected algorithm {expected:?}: {hash:?}")]
    HashAlgorithmMismatch {
        /// The convertHash argument node.
        id: IrId,
        /// The typed hash bytes.
        hash: Vec<u8>,
        /// The expected algorithm bytes.
        expected: Vec<u8>,
    },
    /// `builtins.convertHash` received a hash with the wrong digest length.
    #[error("hash at node {id:?} has the wrong length for {algorithm:?}: {hash:?}")]
    HashWrongLength {
        /// The convertHash argument node.
        id: IrId,
        /// The hash bytes with the wrong length.
        hash: Vec<u8>,
        /// The algorithm whose digest length was expected.
        algorithm: Vec<u8>,
    },
    /// `builtins.convertHash` received an invalid base16 hash.
    #[error("invalid base16 hash at node {id:?}: {hash:?}")]
    InvalidBase16Hash {
        /// The convertHash argument node.
        id: IrId,
        /// The rejected hash bytes.
        hash: Vec<u8>,
    },
    /// `builtins.convertHash` received an invalid Nix base32 hash.
    #[error("invalid nix32 hash at node {id:?}: {hash:?}")]
    InvalidNix32Hash {
        /// The convertHash argument node.
        id: IrId,
        /// The rejected hash bytes.
        hash: Vec<u8>,
    },
    /// `builtins.convertHash` received an invalid base64 hash.
    #[error("invalid base64 hash at node {id:?}: {hash:?}")]
    InvalidBase64Hash {
        /// The convertHash argument node.
        id: IrId,
        /// The rejected hash bytes.
        hash: Vec<u8>,
    },
    /// `builtins.convertHash` received an invalid SRI hash.
    #[error("invalid SRI hash at node {id:?}: {hash:?}")]
    InvalidSriHash {
        /// The convertHash argument node.
        id: IrId,
        /// The rejected hash bytes.
        hash: Vec<u8>,
    },
    /// An internal string-context element violated its shape invariant.
    #[error("invalid string context at node {id:?}")]
    InvalidStringContext {
        /// The node id associated with the malformed context.
        id: IrId,
    },
    /// A Nix list operation failed.
    #[error("list operation failed at node {id:?}: {source}")]
    List {
        /// The node id associated with the list operation.
        id: IrId,
        /// The underlying list failure.
        source: NixListError,
    },
    /// A flat attribute-set operation failed.
    #[error("attribute-set operation failed at node {id:?}: {source}")]
    Attr {
        /// The node id associated with the attrset operation.
        id: IrId,
        /// The underlying attrset failure.
        source: AttrError,
    },
    /// A scalar operation received a value of the wrong Nix type.
    #[error("type error at node {id:?}: expected {expected}, got {actual:?}")]
    Type {
        /// The node id associated with the type check.
        id: IrId,
        /// The expected evaluator value category.
        expected: &'static str,
        /// The actual runtime value tag.
        actual: ValueTag,
    },
    /// An attribute selection found no binding and had no default.
    #[error("missing attribute {symbol:?} at node {id:?}")]
    MissingAttribute {
        /// The select node id.
        id: IrId,
        /// The missing static attribute symbol.
        symbol: Symbol,
    },
    /// A formal-set lambda argument missed a required attribute.
    #[error("missing required formal attribute {symbol:?} at node {id:?}")]
    MissingFormalAttribute {
        /// The application node id.
        id: IrId,
        /// The missing formal attribute symbol.
        symbol: Symbol,
    },
    /// A formal-set lambda argument carried an unexpected attribute.
    #[error("unexpected formal attribute {symbol:?} at node {id:?}")]
    UnexpectedFormalAttribute {
        /// The application node id.
        id: IrId,
        /// The unexpected argument attribute symbol.
        symbol: Symbol,
    },
    /// A dynamic with lookup found no attribute and no supported global fallback.
    #[error("unresolved with variable {symbol:?} at node {id:?}")]
    UnresolvedWithVar {
        /// The with-variable node id.
        id: IrId,
        /// The missing symbol.
        symbol: Symbol,
    },
    /// A boolean-tagged value had an invalid payload.
    ///
    /// Current safe constructors cannot create this state; the check is a
    /// defensive guard for later runtime fast paths and heap-backed values.
    #[error("invalid boolean payload {payload} at node {id:?}")]
    InvalidBoolPayload {
        /// The node id associated with the invalid payload.
        id: IrId,
        /// The invalid boolean payload.
        payload: u64,
    },
    /// The binary operator is outside this evaluator slice.
    #[error("unsupported tree-walk binary operator {op:?} at {id:?}")]
    UnsupportedBinaryOp {
        /// The unsupported node id.
        id: IrId,
        /// The unsupported binary operator.
        op: BinOpKind,
    },
    /// A primitive operation exists in IR but is outside this evaluator slice.
    #[error("unsupported tree-walk primop symbol {symbol:?} at {id:?}")]
    UnsupportedPrimOp {
        /// The primop node id.
        id: IrId,
        /// The unsupported primop symbol.
        symbol: Symbol,
    },
    /// A `builtins` attribute exists but is outside this evaluator slice.
    #[error("unsupported builtins attribute {symbol:?} at node {id:?}")]
    UnsupportedBuiltinAttr {
        /// The select node id.
        id: IrId,
        /// The unsupported builtin attribute symbol.
        symbol: Symbol,
    },
    /// A primitive operation carries the wrong number of lowered arguments.
    #[error("invalid primop arity at {id:?}: expected {expected}, got {actual}")]
    InvalidPrimOpArity {
        /// The primop node id.
        id: IrId,
        /// The primop symbol whose argument list is malformed.
        symbol: Symbol,
        /// The expected number of arguments.
        expected: usize,
        /// The actual number of arguments in the IR child slice.
        actual: usize,
    },
    /// Structural equality for this runtime value type is outside this evaluator slice.
    #[error("unsupported tree-walk equality between {left:?} and {right:?} at {id:?}")]
    UnsupportedEqualityType {
        /// The equality operator node id.
        id: IrId,
        /// The left operand's runtime value tag.
        left: ValueTag,
        /// The right operand's runtime value tag.
        right: ValueTag,
    },
    /// An attribute path shape is outside the evaluator's supported access forms.
    #[error(
        "unsupported tree-walk attribute path {path:?} at {id:?}: segments={segments}, has_dynamic={has_dynamic}"
    )]
    UnsupportedAttrPath {
        /// The access node id.
        id: IrId,
        /// The unsupported attribute-path id.
        path: IrAttrPathId,
        /// The number of path segments.
        segments: usize,
        /// Whether any path segment is dynamic.
        has_dynamic: bool,
    },
    /// A checked integer arithmetic operation overflowed.
    #[error("arithmetic overflow for {op:?} at node {id:?}")]
    ArithmeticOverflow {
        /// The node id of the overflowing operator.
        id: IrId,
        /// The overflowing arithmetic operator.
        op: ArithmeticOp,
    },
    /// A numeric division operation used a zero divisor.
    #[error("division by zero at node {id:?}")]
    DivisionByZero {
        /// The division node id.
        id: IrId,
    },
    /// An `assert` condition evaluated to `false`.
    #[error("assertion failed at node {id:?}")]
    AssertionFailed {
        /// The failed assertion node id.
        id: IrId,
    },
    /// `builtins.throw` raised a catchable evaluation error.
    #[error("thrown error at node {id:?}: {message:?}")]
    Thrown {
        /// The message argument node.
        id: IrId,
        /// The coerced message bytes.
        message: Vec<u8>,
    },
    /// `builtins.abort` raised a fatal evaluation error.
    #[error("evaluation aborted at node {id:?}: {message:?}")]
    Aborted {
        /// The message argument node.
        id: IrId,
        /// The coerced message bytes.
        message: Vec<u8>,
    },
    /// The node kind is outside this evaluator slice.
    #[error("unsupported tree-walk node {kind:?} at {id:?}")]
    UnsupportedNode {
        /// The unsupported node id.
        id: IrId,
        /// The unsupported node kind.
        kind: IrKind,
    },
}

#[cfg(test)]
mod tests {
    use super::super::ThunkState;
    use super::*;
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
        ptr::NonNull,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::compile::{
        EffectClass, FrameInfo, IrArena, IrBinding, IrData, IrInlineCacheSiteId, IrNode, IrShape,
        IrWithChain, lower as lower_ir, resolve as resolve_ast,
    };
    use crate::runtime::builtins::{
        BUILTIN_METADATA, BuiltinDirect, BuiltinEffect, BuiltinMetadata, direct_builtin,
    };
    use crate::string::{ContextElement, StringContext};
    use crate::syntax::{Symbol, SymbolTable, parse_str};
    use crate::value::HeapObject;

    fn lower(source: &str) -> Ir {
        lower_ir(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    fn eval(source: &str) -> Value {
        eval_whnf(&lower(source)).expect("source evaluates")
    }

    fn eval_with_options(source: &str, options: TreeWalkOptions) -> Value {
        eval_whnf_with_options(&lower(source), options).expect("source evaluates")
    }

    fn eval_string_bytes(source: &str) -> Vec<u8> {
        let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
        let string = outcome
            .heap()
            .get_string(outcome.value())
            .expect("result is a heap-owned string");
        string.bytes().to_vec()
    }

    fn eval_string_bytes_with_options(source: &str, options: TreeWalkOptions) -> Vec<u8> {
        let outcome =
            eval_whnf_owned_with_options(&lower(source), options).expect("source evaluates");
        let string = outcome
            .heap()
            .get_string(outcome.value())
            .expect("result is a heap-owned string");
        string.bytes().to_vec()
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after Unix epoch")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("aos-nix-{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp directory creates");
        dir
    }

    fn temp_file_with_bytes(prefix: &str, bytes: &[u8]) -> (PathBuf, PathBuf) {
        let dir = unique_temp_dir(prefix);
        let path = dir.join("data.txt");
        fs::write(&path, bytes).expect("temp file writes");
        (dir, path)
    }

    fn path_source(path: &Path) -> String {
        path.to_str().expect("temp path is UTF-8").to_owned()
    }

    fn nix_string_literal(text: &str) -> String {
        let mut out = String::from("\"");
        for byte in text.bytes() {
            match byte {
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                byte => out.push(char::from(byte)),
            }
        }
        out.push('"');
        out
    }

    fn eval_list_string_bytes(source: &str) -> Vec<Vec<u8>> {
        let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("result is a heap-owned list");
        list.iter()
            .map(|value| {
                outcome
                    .heap()
                    .get_string(*value)
                    .expect("element is a heap-owned string")
                    .bytes()
                    .to_vec()
            })
            .collect()
    }

    fn eval_list_ints(source: &str) -> Vec<i64> {
        let outcome = eval_whnf_owned(&lower(source)).expect("source evaluates");
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("result is a heap-owned list");
        list.iter()
            .map(|value| value.as_int().expect("element is an int"))
            .collect()
    }

    fn symbol_for(ir: &Ir, name: &[u8]) -> Symbol {
        let index = ir
            .symbols
            .symbols()
            .iter()
            .position(|symbol| symbol.as_slice() == name)
            .expect("symbol exists");
        Symbol::new(index as u32)
    }

    fn empty_ir(root: IrId, arena: IrArena) -> Ir {
        Ir {
            root,
            arena,
            symbols: SymbolTable::new(),
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        }
    }

    fn pure_node(kind: IrKind, span: Span, data: IrData) -> IrNode {
        IrNode::new(kind, span, EffectClass::Pure, data)
    }

    fn manual_ir(root: IrId, nodes: Vec<IrNode>) -> Ir {
        empty_ir(root, IrArena::from_raw_parts(nodes, Vec::new()))
    }

    fn manual_ir_with_with_chains(
        root: IrId,
        nodes: Vec<IrNode>,
        symbols: SymbolTable,
        with_chains: Vec<IrWithChain>,
    ) -> Ir {
        Ir {
            root,
            arena: IrArena::from_raw_parts(nodes, Vec::new()),
            symbols,
            frames: Vec::new().into_boxed_slice(),
            with_chains: with_chains.into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        }
    }

    fn manual_ir_with_attr_tables(
        root: IrId,
        nodes: Vec<IrNode>,
        symbols: SymbolTable,
        bindings: Vec<IrBinding>,
        shapes: Vec<IrShape>,
    ) -> Ir {
        Ir {
            root,
            arena: IrArena::from_raw_parts(nodes, Vec::new()),
            symbols,
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: Vec::new().into_boxed_slice(),
            bindings: bindings.into_boxed_slice(),
            shapes: shapes.into_boxed_slice(),
        }
    }

    fn manual_ir_with_attr_paths(
        root: IrId,
        nodes: Vec<IrNode>,
        symbols: SymbolTable,
        attr_paths: Vec<Box<[IrAttrPathSegment]>>,
    ) -> Ir {
        Ir {
            root,
            arena: IrArena::from_raw_parts(nodes, Vec::new()),
            symbols,
            frames: Vec::new().into_boxed_slice(),
            with_chains: Vec::new().into_boxed_slice(),
            attr_paths: attr_paths.into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        }
    }

    fn int_binary_ir(op: BinOpKind, left: i64, right: i64) -> Ir {
        let lhs = IrId::new(0);
        let rhs = IrId::new(1);
        let root = IrId::new(2);
        manual_ir(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(left)),
                pure_node(IrKind::Int, Span::new(2, 3), IrData::Int(right)),
                pure_node(
                    IrKind::BinOp,
                    Span::new(0, 3),
                    IrData::Binary { op, lhs, rhs },
                ),
            ],
        )
    }

    #[test]
    fn evaluates_inline_scalar_literals() {
        assert_eq!(eval("42").as_int(), Ok(42));
        assert_eq!(eval("true").as_bool(), Ok(true));
        assert_eq!(eval("false").as_bool(), Ok(false));
        assert_eq!(eval("null").as_null(), Ok(()));

        let float = eval("1.25").as_float().expect("float value");
        assert_eq!(float.to_bits(), 1.25f64.to_bits());
    }

    #[test]
    fn evaluates_string_literals_with_owned_heap() {
        let ir = lower("\"hello\"");
        let outcome = eval_whnf_owned(&ir).expect("string evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::String);
        assert_eq!(
            outcome
                .heap()
                .get_string(value)
                .expect("string is heap-owned")
                .bytes(),
            b"hello"
        );

        let empty = eval_whnf_owned(&lower("\"\"")).expect("empty string evaluates");
        assert_eq!(
            empty
                .heap()
                .get_string(empty.value())
                .expect("empty string is heap-owned")
                .bytes(),
            b""
        );

        let escaped =
            eval_whnf_owned(&lower("\"line\\n\\\"quoted\\\"\"")).expect("escaped string evaluates");
        assert_eq!(
            escaped
                .heap()
                .get_string(escaped.value())
                .expect("escaped string is heap-owned")
                .bytes(),
            b"line\n\"quoted\""
        );
    }

    #[test]
    fn evaluates_uri_literals_as_strings() {
        assert_eq!(
            eval_string_bytes("https://example.test/path?x=1"),
            b"https://example.test/path?x=1"
        );
        assert_eq!(
            eval_string_bytes("https://example.test + \"/more\""),
            b"https://example.test/more"
        );
        assert_eq!(
            eval("https://example.test == \"https://example.test\"").as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn unary_type_predicate_primops_classify_whnf_values() {
        assert_eq!(eval("builtins.isAttrs { a = 1; }").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isAttrs [ 1 ]").as_bool(), Ok(false));
        assert_eq!(eval("builtins.isList [ 1 ]").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isFunction (x: x)").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isString \"x\"").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isInt 1").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isInt 1.0").as_bool(), Ok(false));
        assert_eq!(eval("builtins.isFloat 1.0").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isBool false").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isNull null").as_bool(), Ok(true));
        assert_eq!(eval("isNull null").as_bool(), Ok(true));
        assert_eq!(
            eval("let isNull = x: false; in isNull null").as_bool(),
            Ok(false)
        );
        assert_eq!(eval("builtins.isPath \"not-path\"").as_bool(), Ok(false));
    }

    #[test]
    fn type_of_primop_returns_nix_type_names() {
        assert_eq!(eval_string_bytes("builtins.typeOf 1"), b"int");
        assert_eq!(eval_string_bytes("builtins.typeOf 1.0"), b"float");
        assert_eq!(eval_string_bytes("builtins.typeOf false"), b"bool");
        assert_eq!(eval_string_bytes("builtins.typeOf null"), b"null");
        assert_eq!(eval_string_bytes("builtins.typeOf \"x\""), b"string");
        assert_eq!(eval_string_bytes("builtins.typeOf [ 1 ]"), b"list");
        assert_eq!(eval_string_bytes("builtins.typeOf { a = 1; }"), b"set");
        assert_eq!(eval_string_bytes("builtins.typeOf (x: x)"), b"lambda");
    }

    #[test]
    fn builtin_lookup_uses_shared_metadata_registry() {
        let metadata_names = BUILTIN_METADATA
            .iter()
            .map(BuiltinMetadata::name)
            .collect::<BTreeSet<_>>();

        assert_eq!(metadata_names.len(), BUILTIN_METADATA.len());
        for metadata in BUILTIN_METADATA {
            assert_eq!(lookup_builtin_by_name(metadata.name()), Some(*metadata));
        }
    }

    #[test]
    fn custom_effectful_unary_builtin_metadata_matches_runtime_impls() {
        for name in [
            b"pathExists".as_slice(),
            b"readDir".as_slice(),
            b"readFile".as_slice(),
            b"readFileType".as_slice(),
        ] {
            assert_eq!(
                direct_builtin(name),
                Some(BuiltinDirect::StrictUnary {
                    effect: BuiltinEffect::Effectful
                })
            );
            let builtin = lookup_builtin_by_name(name).expect("builtin is registered");

            assert_eq!(builtin.first_class_arity(), Some(1));
            assert!(!builtin.docs().summary().is_empty());
        }
    }

    #[test]
    fn tree_walk_options_normalize_store_dir() {
        let defaulted =
            TreeWalkOptions::with_store_dir(Vec::new()).expect("empty store dir defaults");
        assert_eq!(defaulted.store_dir(), b"/nix/store");

        let normalized = TreeWalkOptions::with_store_dir(b"//tmp//aos-store/./".to_vec())
            .expect("absolute store dir normalizes");
        assert_eq!(normalized.store_dir(), b"/tmp/aos-store");

        let parent_normalized = TreeWalkOptions::with_store_dir(b"/tmp/../aos-store".to_vec())
            .expect("parent components reduce");
        assert_eq!(parent_normalized.store_dir(), b"/aos-store");

        let nested_parent_normalized =
            TreeWalkOptions::with_store_dir(b"/tmp/aos-store/../other".to_vec())
                .expect("nested parent components reduce");
        assert_eq!(nested_parent_normalized.store_dir(), b"/tmp/other");

        let mut options = TreeWalkOptions::new();
        options
            .set_store_dir(b"/var//aos/store//".to_vec())
            .expect("absolute store dir sets");
        assert_eq!(options.store_dir(), b"/var/aos/store");

        assert_eq!(
            TreeWalkOptions::with_store_dir(b"relative/store".to_vec())
                .expect_err("relative store dir is rejected"),
            TreeWalkOptionsError::RelativeStoreDir
        );
    }

    #[test]
    fn tree_walk_options_configure_current_system() {
        let defaulted = TreeWalkOptions::new();
        assert_eq!(defaulted.current_system(), None);

        let configured = TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
            .expect("currentSystem configures");
        assert_eq!(
            configured.current_system(),
            Some(b"aarch64-linux".as_slice())
        );

        let mut options = TreeWalkOptions::new();
        options
            .set_current_system(b"x86_64-linux".to_vec())
            .expect("currentSystem sets");
        assert_eq!(options.current_system(), Some(b"x86_64-linux".as_slice()));
        options.clear_current_system();
        assert_eq!(options.current_system(), None);

        assert_eq!(
            TreeWalkOptions::with_current_system(Vec::new())
                .expect_err("empty currentSystem is rejected"),
            TreeWalkOptionsError::EmptyCurrentSystem
        );
    }

    #[test]
    fn tree_walk_options_configure_current_time() {
        let defaulted = TreeWalkOptions::new();
        assert_eq!(defaulted.current_time(), None);

        let configured =
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime configures");
        assert_eq!(configured.current_time(), Some(1_700_000_000));

        let mut options = TreeWalkOptions::new();
        options
            .set_current_time(1_700_000_001)
            .expect("currentTime sets");
        assert_eq!(options.current_time(), Some(1_700_000_001));
        options.clear_current_time();
        assert_eq!(options.current_time(), None);

        assert_eq!(
            TreeWalkOptions::with_current_time(-1).expect_err("negative currentTime is rejected"),
            TreeWalkOptionsError::NegativeCurrentTime
        );
    }

    #[test]
    fn tree_walk_options_configure_environment_variables() {
        let defaulted = TreeWalkOptions::new();
        assert_eq!(defaulted.env_var(b"HOME"), None);

        let configured = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/homeless".to_vec());
        assert_eq!(configured.env_var(b"HOME"), Some(b"/homeless".as_slice()));
        assert_eq!(configured.env_var(b"USER"), None);

        let mut options = TreeWalkOptions::new();
        options.set_env_var(b"USER".to_vec(), b"builder".to_vec());
        assert_eq!(options.env_var(b"USER"), Some(b"builder".as_slice()));
        options.set_env_var(b"USER".to_vec(), b"overridden".to_vec());
        assert_eq!(options.env_var(b"USER"), Some(b"overridden".as_slice()));
        options.clear_env_var(b"USER");
        assert_eq!(options.env_var(b"USER"), None);
    }

    #[test]
    fn static_builtin_selects_are_first_class_functions() {
        assert_eq!(eval("builtins.true").as_bool(), Ok(true));
        assert_eq!(eval("builtins.false").as_bool(), Ok(false));
        assert_eq!(eval("builtins.null").as_null(), Ok(()));
        assert_eq!(eval("builtins.break 7").as_int(), Ok(7));
        assert_eq!(eval("let f = builtins.break; in f 9").as_int(), Ok(9));
        assert_eq!(eval_string_bytes("builtins.storeDir"), b"/nix/store");
        assert_eq!(
            eval_string_bytes_with_options(
                "builtins.storeDir",
                TreeWalkOptions::with_store_dir(b"/tmp/aos-store".to_vec())
                    .expect("store dir is valid")
            ),
            b"/tmp/aos-store"
        );
        assert_eq!(
            eval_string_bytes("builtins.typeOf builtins.storeDir"),
            b"string"
        );
        assert_eq!(eval_string_bytes("builtins.nixVersion"), PINNED_NIX_VERSION);
        assert_eq!(
            eval_string_bytes("builtins.typeOf builtins.nixVersion"),
            b"string"
        );
        assert_eq!(
            eval("builtins.langVersion").as_int(),
            Ok(PINNED_NIX_LANG_VERSION)
        );
        assert_eq!(
            eval_string_bytes("builtins.typeOf builtins.langVersion"),
            b"int"
        );
        assert!(matches!(
            eval_whnf(&lower("builtins.nixVersion null"))
                .expect_err("nixVersion is a value, not a function")
                .kind(),
            TreeWalkErrorKind::Type {
                expected: "lambda",
                actual: ValueTag::String,
                ..
            }
        ));
        assert!(matches!(
            eval_whnf(&lower("builtins.langVersion null"))
                .expect_err("langVersion is a value, not a function")
                .kind(),
            TreeWalkErrorKind::Type {
                expected: "lambda",
                actual: ValueTag::Int,
                ..
            }
        ));
        assert_eq!(
            eval_string_bytes_with_options(
                "builtins.currentSystem",
                TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                    .expect("currentSystem is valid")
            ),
            b"aarch64-linux"
        );
        assert_eq!(
            eval_string_bytes_with_options(
                "builtins.typeOf builtins.currentSystem",
                TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
                    .expect("currentSystem is valid")
            ),
            b"string"
        );
        assert_eq!(
            eval_with_options(
                "builtins.currentTime",
                TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
            )
            .as_int(),
            Ok(1_700_000_000)
        );
        assert_eq!(
            eval_string_bytes_with_options(
                "builtins.typeOf builtins.currentTime",
                TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
            ),
            b"int"
        );
        assert_eq!(
            eval_with_options(
                "builtins.currentTime == builtins.currentTime",
                TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
            )
            .as_bool(),
            Ok(true)
        );
        assert_eq!(eval("builtins ? length").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? break").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? getEnv").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? throw").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? abort").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? tryEval").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? nixVersion").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? langVersion").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? currentSystem").as_bool(), Ok(false));
        assert_eq!(
            eval_with_options(
                "builtins ? currentSystem",
                TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                    .expect("currentSystem is valid")
            )
            .as_bool(),
            Ok(true)
        );
        assert_eq!(eval("builtins ? currentTime").as_bool(), Ok(false));
        assert_eq!(
            eval_with_options(
                "builtins ? currentTime",
                TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
            )
            .as_bool(),
            Ok(true)
        );
        assert_eq!(eval("builtins ? storeDir").as_bool(), Ok(true));
        assert_eq!(eval("builtins ? __missing").as_bool(), Ok(false));
        assert_eq!(eval("builtins ? length.foo").as_bool(), Ok(false));
        assert_eq!(
            eval("builtins.isFunction builtins.length").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.head").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.tail").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.concatLists").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval_string_bytes("builtins.typeOf builtins.length"),
            b"lambda"
        );
        assert_eq!(
            eval("builtins.functionArgs builtins.length == {}").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let f = builtins.length; in f [ 1 2 3 ]").as_int(),
            Ok(3)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.elemAt").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.elem").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let f = builtins.isFunction; in f builtins.convertHash").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.throw").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.abort").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.tryEval").as_bool(),
            Ok(true)
        );
        assert_eq!(eval("builtins.isFunction builtins.all").as_bool(), Ok(true));
        assert_eq!(eval("builtins.isFunction builtins.any").as_bool(), Ok(true));
        assert_eq!(
            eval("builtins.isFunction builtins.concatMap").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.filter").as_bool(),
            Ok(true)
        );
        assert_eq!(eval("builtins.isFunction builtins.map").as_bool(), Ok(true));
        assert_eq!(
            eval("builtins.isFunction builtins.genList").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.groupBy").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.partition").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.foldl'").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.substring").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.replaceStrings").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isFunction builtins.sort").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let x = builtins.break (1 / 0); in 42").as_int(),
            Ok(42)
        );
        assert!(matches!(
            eval_whnf(&lower("builtins.length (builtins.break [ 1 2 ])"))
                .expect_err("length sees the break result as an unforced thunk")
                .kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Thunk,
                ..
            }
        ));
        assert!(matches!(
            eval_whnf(&lower(
                "builtins.length (let f = builtins.break; in f [ 1 2 ])"
            ))
            .expect_err("first-class break preserves the returned thunk")
            .kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Thunk,
                ..
            }
        ));
        assert!(matches!(
            eval_whnf(&lower("builtins.hasAttr \"x\" (builtins.break { x = 1; })"))
                .expect_err("hasAttr sees the break result as an unforced thunk")
                .kind(),
            TreeWalkErrorKind::Type {
                expected: "attrs",
                actual: ValueTag::Thunk,
                ..
            }
        ));
        assert_eq!(eval("builtins.__missing or 42").as_int(), Ok(42));
        assert_eq!(eval("builtins.__missing.foo or 42").as_int(), Ok(42));
        assert_eq!(eval("builtins.length.foo or 42").as_int(), Ok(42));
        assert_eq!(
            eval_string_bytes("builtins.storeDir or \"fallback\""),
            b"/nix/store"
        );
        assert_eq!(
            eval_string_bytes("builtins.nixVersion or \"fallback\""),
            PINNED_NIX_VERSION
        );
        assert_eq!(
            eval("builtins.langVersion or 42").as_int(),
            Ok(PINNED_NIX_LANG_VERSION)
        );
        assert_eq!(
            eval_string_bytes("builtins.currentSystem or \"fallback\""),
            b"fallback"
        );
        assert_eq!(
            eval_string_bytes_with_options(
                "builtins.currentSystem or \"fallback\"",
                TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
                    .expect("currentSystem is valid")
            ),
            b"aarch64-linux"
        );
        assert_eq!(eval("builtins.currentTime or 42").as_int(), Ok(42));
        assert_eq!(
            eval_with_options(
                "builtins.currentTime or 42",
                TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid")
            )
            .as_int(),
            Ok(1_700_000_000)
        );
    }

    #[test]
    fn known_but_unimplemented_builtin_selects_do_not_use_defaults() {
        for (source, name) in [
            ("builtins.exec or 42", b"exec".as_slice()),
            ("builtins.fetchClosure or 42", b"fetchClosure".as_slice()),
            ("builtins.outputOf or 42", b"outputOf".as_slice()),
            ("builtins.scopedImport or 42", b"scopedImport".as_slice()),
            ("builtins.toHashFormat or 42", b"toHashFormat".as_slice()),
        ] {
            let ir = lower(source);
            let error = eval_whnf_owned(&ir).expect_err("known builtin does not use default");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::UnsupportedBuiltinAttr {
                    id: ir.root,
                    symbol: symbol_for(&ir, name),
                }
            );
        }
    }

    #[test]
    fn throw_and_abort_raise_distinct_errors() {
        let ir = lower("builtins.throw \"boom\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let message_id = args[0];
        let message_span = ir.arena.node(message_id).expect("message exists").span;

        let error = eval_whnf_owned(&ir).expect_err("throw raises");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Thrown {
                id: message_id,
                message: b"boom".to_vec(),
            }
        );
        assert_eq!(error.span(), message_span);

        let error = eval_whnf_owned(&lower("let f = builtins.throw; in f \"boom\""))
            .expect_err("first-class throw raises");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"boom");

        let ir = lower("builtins.abort \"boom\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let message_id = args[0];
        let message_span = ir.arena.node(message_id).expect("message exists").span;

        let error = eval_whnf_owned(&ir).expect_err("abort raises");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Aborted {
                id: message_id,
                message: b"boom".to_vec(),
            }
        );
        assert_eq!(error.span(), message_span);

        let error = eval_whnf_owned(&lower("let f = builtins.abort; in f \"boom\""))
            .expect_err("first-class abort raises");
        let TreeWalkErrorKind::Aborted { message, .. } = error.kind() else {
            panic!("expected aborted error");
        };
        assert_eq!(message, b"boom");
    }

    #[test]
    fn throw_and_abort_coerce_messages_before_raising() {
        let ir = lower("builtins.throw { __toString = self: \"coerced\"; }");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let message_id = args[0];

        let error = eval_whnf_owned(&ir).expect_err("throw raises after coercion");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Thrown {
                id: message_id,
                message: b"coerced".to_vec(),
            }
        );

        for source in ["builtins.throw 1", "builtins.abort 1"] {
            let ir = lower(source);
            let root = ir.arena.node(ir.root).expect("root exists");
            let IrData::PrimOp { args, .. } = root.data else {
                panic!("root is a primop");
            };
            let args = ir.arena.child_slice(args).expect("primop args exist");
            let message_id = args[0];
            let message_span = ir.arena.node(message_id).expect("message exists").span;

            let error = eval_whnf_owned(&ir).expect_err("message coercion fails first");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::Type {
                    id: message_id,
                    expected: "string",
                    actual: ValueTag::Int,
                },
                "{source}"
            );
            assert_eq!(error.span(), message_span, "{source}");
        }
    }

    #[test]
    fn throw_and_abort_remain_lazy_until_demanded() {
        assert_eq!(
            eval("let x = builtins.throw \"boom\"; in 1").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("{ a = builtins.abort \"boom\"; b = 2; }.b").as_int(),
            Ok(2)
        );

        let error = eval_whnf_owned(&lower("builtins.seq (builtins.throw \"boom\") 1"))
            .expect_err("seq demands throw");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"boom");

        let error = eval_whnf_owned(&lower("builtins.deepSeq [ (builtins.abort \"boom\") ] 1"))
            .expect_err("deepSeq demands abort");
        let TreeWalkErrorKind::Aborted { message, .. } = error.kind() else {
            panic!("expected aborted error");
        };
        assert_eq!(message, b"boom");
    }

    #[test]
    fn try_eval_catches_throw_and_assertion_failures() {
        assert_eq!(
            eval("(builtins.tryEval (builtins.throw \"boom\")).success").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("(builtins.tryEval (builtins.throw \"boom\")).value").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("(let t = builtins.tryEval; in t (builtins.throw \"boom\")).success").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("(builtins.tryEval (assert false; 1)).success").as_bool(),
            Ok(false)
        );
        assert_eq!(eval("(builtins.tryEval 7).success").as_bool(), Ok(true));
        assert_eq!(eval("(builtins.tryEval 7).value").as_int(), Ok(7));
    }

    #[test]
    fn try_eval_is_shallow() {
        assert_eq!(
            eval("(builtins.tryEval { x = builtins.throw \"boom\"; }).success").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.isAttrs (builtins.tryEval { x = builtins.throw \"boom\"; }).value")
                .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("(builtins.tryEval [ (builtins.throw \"boom\") ]).success").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.length (builtins.tryEval [ (builtins.throw \"boom\") ]).value").as_int(),
            Ok(1)
        );

        let error = eval_whnf_owned(&lower(
            "builtins.deepSeq (builtins.tryEval { x = builtins.throw \"boom\"; }) true",
        ))
        .expect_err("deepSeq demands the latent throw inside tryEval's value");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"boom");
    }

    #[test]
    fn try_eval_does_not_catch_fatal_or_type_errors() {
        let error = eval_whnf_owned(&lower("builtins.tryEval (builtins.abort \"boom\")"))
            .expect_err("tryEval does not catch abort");
        let TreeWalkErrorKind::Aborted { message, .. } = error.kind() else {
            panic!("expected aborted error");
        };
        assert_eq!(message, b"boom");

        let error = eval_whnf_owned(&lower("builtins.tryEval (1 + true)"))
            .expect_err("tryEval does not catch type errors");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "number",
                actual: ValueTag::Bool,
                ..
            }
        ));

        let error = eval_whnf_owned(&lower("builtins.tryEval ({ }).missing"))
            .expect_err("tryEval does not catch missing attrs");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::MissingAttribute { .. }
        ));

        let error = eval_whnf_owned(&lower("builtins.tryEval (builtins.elemAt [] 0)"))
            .expect_err("tryEval does not catch list bounds errors");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::ListIndexOutOfBounds { .. }
        ));
    }

    #[test]
    fn unavailable_current_system_behaves_like_missing_attr() {
        let ir = lower("builtins.currentSystem");
        let error = eval_whnf_owned(&ir).expect_err("currentSystem is unavailable");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::MissingAttribute {
                id: ir.root,
                symbol: symbol_for(&ir, b"currentSystem")
            }
        );
    }

    #[test]
    fn unavailable_current_time_behaves_like_missing_attr() {
        let ir = lower("builtins.currentTime");
        let error = eval_whnf_owned(&ir).expect_err("currentTime is unavailable");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::MissingAttribute {
                id: ir.root,
                symbol: symbol_for(&ir, b"currentTime")
            }
        );
    }

    #[test]
    fn bare_current_time_remains_unresolved_global() {
        let ir = lower("currentTime");
        let error = eval_whnf_owned_with_options(
            &ir,
            TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime is valid"),
        )
        .expect_err("currentTime is not a bare global");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedNode {
                id: ir.root,
                kind: IrKind::GlobalVar,
            }
        );
    }

    #[test]
    fn first_class_builtin_selects_respect_shadowing() {
        assert_eq!(
            eval("let builtins = { length = x: 42; }; in builtins.length [ 1 ]").as_int(),
            Ok(42)
        );
        assert_eq!(
            eval("let builtins = {}; in builtins.length or 42").as_int(),
            Ok(42)
        );
        assert_eq!(
            eval_string_bytes("let builtins = { storeDir = \"local\"; }; in builtins.storeDir"),
            b"local"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { currentSystem = \"local\"; }; in builtins.currentSystem"
            ),
            b"local"
        );
        assert_eq!(
            eval("let builtins = { break = value: 42; }; in builtins.break 1").as_int(),
            Ok(42)
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { getEnv = name: \"local\"; }; in builtins.getEnv \"HOME\""
            ),
            b"local"
        );
    }

    #[test]
    fn length_primop_returns_list_spine_length_without_forcing_elements() {
        assert_eq!(eval("builtins.length []").as_int(), Ok(0));
        assert_eq!(eval("builtins.length [ 1 (1 / 0) true ]").as_int(), Ok(3));
        assert_eq!(
            eval("let builtins = { length = x: 42; }; in builtins.length [ 1 ]").as_int(),
            Ok(42)
        );
    }

    #[test]
    fn length_primop_type_checks_argument() {
        let ir = lower("builtins.length 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("length requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn attr_names_primop_returns_sorted_names_without_forcing_values() {
        assert_eq!(
            eval_list_string_bytes("builtins.attrNames { z = 1 / 0; a = 2; b = true; }"),
            vec![b"a".to_vec(), b"b".to_vec(), b"z".to_vec()]
        );
        assert_eq!(
            eval_list_string_bytes("builtins.attrNames { a = 1; A = 1; aa = 1; _ = 1; }"),
            vec![b"A".to_vec(), b"_".to_vec(), b"a".to_vec(), b"aa".to_vec()]
        );
        assert_eq!(
            eval_list_string_bytes(
                "let builtins = { attrNames = x: [ \"local\" ]; }; in builtins.attrNames { a = 1; }"
            ),
            vec![b"local".to_vec()]
        );
    }

    #[test]
    fn attr_names_primop_type_checks_argument() {
        let ir = lower("builtins.attrNames 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("attrNames requires an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn attr_values_primop_returns_sorted_values_without_forcing_them() {
        let ir = lower("builtins.attrValues { z = 1 / 0; a = 2; }");
        let span = ir.arena.node(ir.root).expect("root exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator.eval_root().expect("attrValues evaluates");
        let values = {
            let list = evaluator
                .heap
                .get_list(value)
                .expect("result is a heap-owned list");
            list.as_slice().to_vec()
        };

        assert_eq!(values.len(), 2);
        let first = evaluator
            .force_value(ir.root, span, values[0])
            .expect("first value forces");
        assert_eq!(first.as_int(), Ok(2));
        let lazy_division = values[1];
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(lazy_division)
            .expect("second value remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );

        assert_eq!(
            eval_list_string_bytes(
                "let builtins = { attrValues = x: [ \"local\" ]; }; in builtins.attrValues { a = 1; }"
            ),
            vec![b"local".to_vec()]
        );
    }

    #[test]
    fn attr_values_primop_type_checks_argument() {
        let ir = lower("builtins.attrValues 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("attrValues requires an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn tail_primop_returns_tail_without_forcing_elements() {
        let ir = lower("builtins.tail [ 1 (1 / 0) true ]");
        let outcome = eval_whnf_owned(&ir).expect("tail evaluates");
        let heap = outcome.heap();
        let list = heap
            .get_list(outcome.value())
            .expect("tail result is heap-owned");

        assert_eq!(list.len(), 2);
        let lazy_division = list.get(0).expect("first tail element");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("first tail element remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
        assert_eq!(
            list.get(1).expect("second tail element").as_bool(),
            Ok(true)
        );

        assert_eq!(
            eval_list_string_bytes(
                "let builtins = { tail = x: [ \"local\" ]; }; in builtins.tail [ 1 ]"
            ),
            vec![b"local".to_vec()]
        );
        assert_eq!(
            eval_list_ints("let f = builtins.tail; in f [ 1 2 3 ]"),
            vec![2, 3]
        );

        let ir = lower("let f = builtins.tail; in f [ 1 (1 / 0) true ]");
        let outcome = eval_whnf_owned(&ir).expect("first-class tail evaluates");
        let heap = outcome.heap();
        let list = heap
            .get_list(outcome.value())
            .expect("tail result is heap-owned");

        assert_eq!(list.len(), 2);
        let lazy_division = list.get(0).expect("first tail element");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
    }

    #[test]
    fn tail_primop_rejects_empty_lists() {
        let ir = lower("builtins.tail []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("tail requires a non-empty list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::EmptyListPrimOp {
                id: argument,
                op: "tail"
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn tail_primop_type_checks_argument() {
        let ir = lower("builtins.tail 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("tail requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn function_args_primop_describes_lambda_formals_without_forcing_defaults() {
        let simple = eval_whnf_owned(&lower("builtins.functionArgs (x: x)"))
            .expect("functionArgs evaluates");
        let attrs = simple
            .heap()
            .get_attrs(simple.value())
            .expect("simple lambda result is attrs");
        assert!(attrs.is_empty());

        let ir = lower("builtins.functionArgs ({ b ? (1 / 0), a, ... }@args: a)");
        let outcome = eval_whnf_owned(&ir).expect("functionArgs evaluates");
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("formal-set lambda result is attrs");
        let entries = attrs
            .iter_lexicographic()
            .map(|entry| {
                (
                    ir.symbols
                        .resolve(entry.key)
                        .expect("entry key resolves")
                        .to_vec(),
                    entry.value.as_bool().expect("entry value is bool"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![(b"a".to_vec(), false), (b"b".to_vec(), true)]);
        assert_eq!(
            eval("let r = builtins.functionArgs ({ b ? (1 / 0), a }: a); in r.a == false && r.b")
                .as_bool(),
            Ok(true)
        );

        assert_eq!(
            eval("let builtins = { functionArgs = f: { local = true; }; }; in (builtins.functionArgs (x: x)).local")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn function_args_primop_type_checks_argument() {
        let ir = lower("builtins.functionArgs 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("functionArgs requires a lambda");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "function",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn list_to_attrs_primop_builds_attrs_with_first_wins_duplicates() {
        assert_eq!(
            eval_list_string_bytes(
                "builtins.attrNames (builtins.listToAttrs [ { name = \"b\"; value = 1; } { name = \"a\"; value = 2; } ])"
            ),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        assert_eq!(
            eval("(builtins.listToAttrs [ { name = \"a\"; value = 1; } { name = \"a\"; value = 1 / 0; } ]).a")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("(builtins.listToAttrs [ { name = \"a\"; value = 1; } { name = \"a\"; } ]).a")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("let builtins = { listToAttrs = list: { local = true; }; }; in (builtins.listToAttrs []).local")
                .as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.listToAttrs [ { name = \"a\"; value = 1 / 0; } ]");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("listToAttrs primop evaluates");
        let attrs = evaluator
            .heap
            .get_attrs(value)
            .expect("listToAttrs result is attrs");
        let entry = attrs
            .iter_lexicographic()
            .next()
            .expect("listToAttrs result has one attr");
        assert_eq!(ir.symbols.resolve(entry.key), Some(b"a".as_slice()));
        let value = entry.value;
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("attribute value remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn list_to_attrs_primop_type_checks_list_elements_and_names() {
        let ir = lower("builtins.listToAttrs 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("listToAttrs requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.listToAttrs [ 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("listToAttrs requires element attrsets");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.listToAttrs [ { name = 1; value = 2; } ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("listToAttrs requires string names");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn list_to_attrs_primop_reports_missing_name_value_pairs() {
        let ir = lower("builtins.listToAttrs [ {} ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let mut evaluator = TreeWalk::new(&ir);

        let error = evaluator
            .eval_root()
            .expect_err("listToAttrs requires a name attribute");

        let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
            panic!("expected missing name attribute");
        };
        assert_eq!(id, argument);
        assert_eq!(evaluator.symbols.resolve(symbol), Some(b"name".as_slice()));

        let ir = lower("builtins.listToAttrs [ { name = \"a\"; } ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let mut evaluator = TreeWalk::new(&ir);

        let error = evaluator
            .eval_root()
            .expect_err("listToAttrs requires a value attribute");

        let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
            panic!("expected missing value attribute");
        };
        assert_eq!(id, argument);
        assert_eq!(evaluator.symbols.resolve(symbol), Some(b"value".as_slice()));
    }

    #[test]
    fn concat_lists_primop_flattens_spines_without_forcing_elements() {
        assert_eq!(
            eval_list_ints("builtins.concatLists [ [ 1 ] [] [ 2 3 ] ]"),
            vec![1, 2, 3]
        );
        assert_eq!(eval_list_ints("builtins.concatLists []"), Vec::<i64>::new());
        assert_eq!(
            eval_list_ints("let f = builtins.concatLists; in f [ [ 1 ] [] [ 2 3 ] ]"),
            vec![1, 2, 3]
        );

        let ir = lower("builtins.concatLists [ [ true (1 / 0) ] [] ]");
        let outcome = eval_whnf_owned(&ir).expect("concatLists evaluates");
        let heap = outcome.heap();
        let list = heap
            .get_list(outcome.value())
            .expect("concatLists result is a list");

        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));
        let lazy_division = list.get(1).expect("second");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("inner list element remains lazy");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );

        let ir = lower("let f = builtins.concatLists; in f [ [ true (1 / 0) ] [] ]");
        let outcome = eval_whnf_owned(&ir).expect("first-class concatLists evaluates");
        let heap = outcome.heap();
        let list = heap
            .get_list(outcome.value())
            .expect("concatLists result is a list");

        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));
        assert_eq!(list.get(1).expect("second").tag(), ValueTag::Thunk);
    }

    #[test]
    fn concat_lists_primop_type_checks_outer_and_inner_lists() {
        let ir = lower("builtins.concatLists 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("concatLists requires an outer list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.concatLists [ [ 1 ] 2 [ 3 ] ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("concatLists requires inner lists");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.concatLists (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];

        let error = eval_whnf_owned(&ir).expect_err("outer list is forced first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );

        let ir = lower("builtins.concatLists [ [ 1 ] (1 / 0) ]");
        let error = eval_whnf_owned(&ir).expect_err("inner lists are forced in order");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn head_primop_returns_first_element_without_forcing_list_elements() {
        let ir = lower("builtins.head [ (1 / 0) true ]");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("head primop evaluates");
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("head result remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );

        assert_eq!(eval("builtins.head [ true (1 / 0) ]").as_bool(), Ok(true));
        assert_eq!(
            eval("let f = builtins.head; in f [ true (1 / 0) ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval_string_bytes("let builtins = { head = x: \"local\"; }; in builtins.head [ 1 ]"),
            b"local"
        );
    }

    #[test]
    fn head_primop_rejects_empty_lists() {
        let ir = lower("builtins.head []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("head requires a non-empty list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::EmptyListPrimOp {
                id: argument,
                op: "head"
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn head_primop_type_checks_argument() {
        let ir = lower("builtins.head 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("head requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn elem_at_primop_returns_indexed_element_without_forcing_other_elements() {
        assert_eq!(
            eval("builtins.elemAt [ true (1 / 0) false ] 0").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let f = builtins.elemAt; in f [ 1 2 ] 1").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let xs = [ 1 2 ]; n = 1; in builtins.elemAt xs n").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let builtins = { elemAt = xs: n: 42; }; in builtins.elemAt [ true ] 0").as_int(),
            Ok(42)
        );

        let ir = lower("builtins.elemAt [ true (1 / 0) false ] 1");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("elemAt primop evaluates");
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("selected element remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn elem_at_primop_type_checks_arguments_in_order() {
        let ir = lower("builtins.elemAt 1 true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt checks the index before the list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: index,
                expected: "int",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), index_span);

        let ir = lower("builtins.elemAt (1 / 0) true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt checks index type before forcing list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: index,
                expected: "int",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), index_span);

        let ir = lower("builtins.elemAt 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt forces the index before checking the list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: index }
        );
        assert_eq!(error.span(), index_span);

        let error = eval_whnf_owned(&lower(
            "let f = builtins.elemAt; in f (builtins.throw \"list\") (builtins.throw \"index\")",
        ))
        .expect_err("first-class elemAt forces the index before the list");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"index");

        let ir = lower("builtins.elemAt [] true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let index = args[1];
        let index_span = ir.arena.node(index).expect("index argument exists").span;

        let error = eval_whnf(&ir).expect_err("elemAt requires an integer index");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: index,
                expected: "int",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), index_span);
    }

    #[test]
    fn elem_at_primop_rejects_out_of_range_indexes() {
        for (source, expected_index) in [
            ("builtins.elemAt [ true ] 1", 1),
            ("builtins.elemAt [ true ] (-1)", -1),
        ] {
            let ir = lower(source);
            let root = ir.arena.node(ir.root).expect("root exists");
            let IrData::PrimOp { args, .. } = root.data else {
                panic!("root is a primop");
            };
            let args = ir.arena.child_slice(args).expect("primop args exist");
            let index = args[1];
            let index_span = ir.arena.node(index).expect("index argument exists").span;

            let error = eval_whnf(&ir).expect_err("elemAt requires an in-range index");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::ListIndexOutOfBounds {
                    id: index,
                    index: expected_index,
                    len: 1
                }
            );
            assert_eq!(error.span(), index_span);
        }
    }

    #[test]
    fn elem_primop_scans_list_with_structural_equality() {
        assert_eq!(eval("builtins.elem 2 [ 1 2 (1 / 0) ]").as_bool(), Ok(true));
        assert_eq!(eval("builtins.elem 3 [ 1 2 ]").as_bool(), Ok(false));
        assert_eq!(
            eval("let f = builtins.elem; in f 2 [ 1 2 (1 / 0) ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let f = builtins.elem; in f 3 [ 1 2 ]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("builtins.elem { a = 1; } [ { a = 1; } { a = 1 / 0; } ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let f = x: x; in builtins.elem f [ f ]").as_bool(),
            Ok(true)
        );
        assert_eq!(eval("builtins.elem (x: x) [ (x: x) ]").as_bool(), Ok(false));
        assert_eq!(
            eval("let v = { a = x: x; }; in builtins.elem v.a [ v.a ]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let xs = [ xs ]; in builtins.elem xs xs").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let xs = [ xs ]; f = builtins.elem; in f xs xs").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let s = rec { a = s; }; in builtins.elem s [ s ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let xs = [ (1 / 0) ]; in builtins.elem xs [ xs ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(
                "let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in builtins.elem nan [ nan ]"
            )
            .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(
                "builtins.elem ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) [ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ]"
            )
            .as_bool(),
            Ok(false)
        );
        assert_eq!(eval("builtins.elem (1 / 0) []").as_bool(), Ok(false));
        assert_eq!(
            eval("let builtins = { elem = value: list: false; }; in builtins.elem 1 [ 1 ]")
                .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn elem_primop_type_checks_list_before_candidate() {
        let ir = lower("builtins.elem (1 / 0) 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf(&ir).expect_err("elem checks list type before candidate");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.elem 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf(&ir).expect_err("elem forces the list before the candidate");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
        assert_eq!(error.span(), list_span);

        let error = eval_whnf_owned(&lower("let f = builtins.elem; in f (1 / 0) 1"))
            .expect_err("first-class elem checks list before candidate");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Int,
                ..
            }
        ));

        let error = eval_whnf_owned(&lower("let f = builtins.elem; in f 1 (1 / 0)"))
            .expect_err("first-class elem forces list before candidate");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let ir = lower("builtins.elem 2 [ 1 (1 / 0) ]");
        let error = eval_whnf_owned(&ir).expect_err("elem scans until match or error");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let ir = lower("let x = 1 / 0; in builtins.elem x [ x ]");
        let error = eval_whnf_owned(&ir).expect_err("elem forces shared throwing candidates");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let ir = lower("let s = { x = 1 / 0; }; v = { a = s; }; in builtins.elem v.a [ v.a ]");
        let error = eval_whnf_owned(&ir).expect_err("elem does not hide selected attrset errors");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn all_and_any_primops_short_circuit_over_lazy_elements() {
        assert_eq!(
            eval("builtins.all (x: x < 3) [ 1 2 3 ]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("builtins.all (x: x < 4) [ 1 2 3 ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.any (x: x == 2) [ 1 2 (1 / 0) ]").as_bool(),
            Ok(true)
        );
        assert_eq!(eval("builtins.any (x: false) []").as_bool(), Ok(false));
        assert_eq!(eval("builtins.all (x: true) []").as_bool(), Ok(true));
        assert_eq!(
            eval("builtins.all (x: false) [ (1 / 0) ]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("builtins.any (x: true) [ (1 / 0) ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.all builtins.isInt [ 1 2 ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.any builtins.isString [ 1 \"x\" ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let a = builtins.all; in a (x: x) [ true ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let a = builtins.any; in a (x: x) [ false true ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let p = x: x; xs = [ true ]; in builtins.all p xs").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let builtins = { all = pred: list: false; }; in builtins.all (x: true) []")
                .as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let builtins = { any = pred: list: true; }; in builtins.any (x: false) []")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn all_and_any_primops_check_predicate_then_list_then_result() {
        let ir = lower("builtins.all (1 / 0) []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let predicate = args[0];
        let predicate_span = ir
            .arena
            .node(predicate)
            .expect("predicate argument exists")
            .span;

        let error = eval_whnf(&ir).expect_err("all forces predicate before empty list result");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: predicate }
        );
        assert_eq!(error.span(), predicate_span);

        let ir = lower("builtins.any 1 []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let predicate = args[0];
        let predicate_span = ir
            .arena
            .node(predicate)
            .expect("predicate argument exists")
            .span;

        let error = eval_whnf(&ir).expect_err("any requires a predicate function");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: predicate,
                expected: "function",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), predicate_span);

        let error = eval_whnf_owned(&lower(
            "let a = builtins.all; in a (builtins.throw \"predicate\") (builtins.throw \"list\")",
        ))
        .expect_err("first-class all forces predicate before list");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"predicate");

        let error = eval_whnf_owned(&lower(
            "let a = builtins.any; in a (builtins.throw \"predicate\") (builtins.throw \"list\")",
        ))
        .expect_err("first-class any forces predicate before list");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"predicate");

        let error = eval_whnf_owned(&lower("let a = builtins.any; in a (x: false) 1"))
            .expect_err("first-class any requires a list");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Int,
                ..
            }
        ));

        let ir = lower("builtins.all (x: true) 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf(&ir).expect_err("all requires a list after checking predicate");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);

        for source in [
            "builtins.all (x: 1) [ \"a\" ]",
            "builtins.any (x: 1) [ \"a\" ]",
        ] {
            let ir = lower(source);
            let root = ir.arena.node(ir.root).expect("root exists");
            let IrData::PrimOp { args, .. } = root.data else {
                panic!("root is a primop");
            };
            let args = ir.arena.child_slice(args).expect("primop args exist");
            let predicate = args[0];
            let predicate_span = ir
                .arena
                .node(predicate)
                .expect("predicate argument exists")
                .span;

            let error = eval_whnf(&ir).expect_err("predicate result must be bool");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::Type {
                    id: predicate,
                    expected: "bool",
                    actual: ValueTag::Int,
                }
            );
            assert_eq!(error.span(), predicate_span);
        }
    }

    #[test]
    fn concat_map_primop_concatenates_mapped_lists_without_forcing_elements() {
        assert_eq!(
            eval("builtins.length (builtins.concatMap (x: [ x x ]) [ 1 2 ])").as_int(),
            Ok(4)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.concatMap (x: [ x x ]) [ 1 2 ]) 0").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.concatMap (x: [ x x ]) [ 1 2 ]) 3").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.length (builtins.concatMap (x: []) [ (1 / 0) ])").as_int(),
            Ok(0)
        );
        assert_eq!(
            eval("builtins.length (builtins.concatMap (x: [ (1 / 0) ]) [ 1 ])").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.concatMap builtins.attrValues [ { a = 1; } { b = 2; } ]) 1")
                .as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.length (let f = builtins.concatMap; in f builtins.attrValues [ { a = 1; } { b = 2; } ])")
                .as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let f = x: []; xs = [ (1 / 0) ]; in builtins.length (builtins.concatMap f xs)")
                .as_int(),
            Ok(0)
        );
        assert_eq!(
            eval("let builtins = { concatMap = f: list: [ 42 ]; }; in builtins.concatMap (x: []) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn concat_map_primop_checks_function_then_list_then_results() {
        let ir = lower("builtins.concatMap (1 / 0) []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let function = args[0];
        let function_span = ir
            .arena
            .node(function)
            .expect("function argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("concatMap forces function before list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: function }
        );
        assert_eq!(error.span(), function_span);

        let ir = lower("builtins.concatMap 1 []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let function = args[0];
        let function_span = ir
            .arena
            .node(function)
            .expect("function argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("concatMap requires a function");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: function,
                expected: "function",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), function_span);

        let error = eval_whnf_owned(&lower(
            "let f = builtins.concatMap; in f (builtins.throw \"function\") (builtins.throw \"list\")",
        ))
        .expect_err("first-class concatMap forces function before list");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"function");

        let error = eval_whnf_owned(&lower("let f = builtins.concatMap; in f (x: [ x ]) 1"))
            .expect_err("first-class concatMap requires a list");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Int,
                ..
            }
        ));

        let error = eval_whnf_owned(&lower("let f = builtins.concatMap; in f (x: 1) [ \"a\" ]"))
            .expect_err("first-class concatMap requires list results");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Int,
                ..
            }
        ));

        let ir = lower("builtins.concatMap (x: [ x ]) 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("concatMap checks list after function");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.concatMap (x: 1) [ \"a\" ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let function = args[0];
        let function_span = ir
            .arena
            .node(function)
            .expect("function argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("concatMap requires list results");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: function,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), function_span);
    }

    #[test]
    fn group_by_primop_groups_by_string_key_without_forcing_elements() {
        assert_eq!(
            eval_list_string_bytes(
                "builtins.attrNames (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ])"
            ),
            vec![b"big".to_vec(), b"small".to_vec()]
        );
        assert_eq!(
            eval("builtins.length (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).small")
                .as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).small 0")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.groupBy (x: if x < 3 then \"small\" else \"big\") [ 1 2 3 ]).big 0")
                .as_int(),
            Ok(3)
        );
        assert_eq!(
            eval("builtins.length (builtins.groupBy builtins.typeOf [ 1 \"x\" 2 ]).int").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.length (let f = builtins.groupBy; in f builtins.typeOf [ 1 \"x\" 2 ]).string")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.length (builtins.groupBy (x: \"k\") [ (1 / 0) ]).k").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval(
                "let f = x: \"k\"; xs = [ (1 / 0) ]; in builtins.length (builtins.groupBy f xs).k"
            )
            .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("let g = builtins.groupBy; in builtins.length (g (x: \"k\") [ (1 / 0) ]).k")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.groupBy (x: x) [ \"b\" \"a\" \"b\" ]).b 1 == \"b\"")
                .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let builtins = { groupBy = f: list: { local = [ 42 ]; }; }; in builtins.groupBy (x: \"k\") [] == { local = [ 42 ]; }")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn group_by_primop_checks_function_then_list_then_key_results() {
        let ir = lower("builtins.groupBy (1 / 0) []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let function = args[0];
        let function_span = ir
            .arena
            .node(function)
            .expect("function argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("groupBy forces function before list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: function }
        );
        assert_eq!(error.span(), function_span);

        let ir = lower("builtins.groupBy 1 []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let function = args[0];
        let function_span = ir
            .arena
            .node(function)
            .expect("function argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("groupBy requires a function");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: function,
                expected: "function",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), function_span);

        let error = eval_whnf_owned(&lower(
            "let f = builtins.groupBy; in f (builtins.throw \"function\") (builtins.throw \"list\")",
        ))
        .expect_err("first-class groupBy forces function before list");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"function");

        let error = eval_whnf_owned(&lower("let f = builtins.groupBy; in f (x: \"k\") 1"))
            .expect_err("first-class groupBy requires a list");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Int,
                ..
            }
        ));

        let error = eval_whnf_owned(&lower("let f = builtins.groupBy; in f (x: 1) [ \"a\" ]"))
            .expect_err("first-class groupBy requires string keys");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "string",
                actual: ValueTag::Int,
                ..
            }
        ));

        let ir = lower("builtins.groupBy (x: \"k\") 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("groupBy checks list after function");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.groupBy (x: 1) [ \"a\" ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let function = args[0];
        let function_span = ir
            .arena
            .node(function)
            .expect("function argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("groupBy requires string keys");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: function,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), function_span);
    }

    #[test]
    fn gen_list_primop_builds_lazy_indexed_elements() {
        assert_eq!(
            eval("builtins.length (builtins.genList (x: builtins.throw \"generated\") 2)").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.genList (x: x * x) 5) 4").as_int(),
            Ok(16)
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.concatStringsSep \",\" (builtins.genList builtins.toString 3)"
            ),
            b"0,1,2"
        );
        assert_eq!(
            eval("let g = builtins.genList; in builtins.elemAt (g (x: x + 1) 2) 1").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let n = 2; f = x: x + 1; in builtins.elemAt (builtins.genList f n) 1").as_int(),
            Ok(2)
        );

        let error = eval_whnf_owned(&lower(
            "builtins.elemAt (builtins.genList (x: builtins.throw \"generated\") 2) 0",
        ))
        .expect_err("generated element is forced only when selected");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"generated");
    }

    #[test]
    fn gen_list_primop_checks_length_before_generator() {
        let ir =
            lower("builtins.genList (builtins.throw \"function\") (builtins.throw \"length\")");

        let error = eval_whnf_owned(&ir).expect_err("genList forces length before generator");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"length");

        let error = eval_whnf_owned(&lower(
            "let g = builtins.genList; in g (builtins.throw \"function\") (builtins.throw \"length\")",
        ))
        .expect_err("first-class genList forces length before generator");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"length");

        let ir = lower("builtins.genList 1 0");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let generator = args[0];
        let generator_span = ir
            .arena
            .node(generator)
            .expect("generator argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("genList checks generator after length");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: generator,
                expected: "function",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), generator_span);

        let error = eval_whnf_owned(&lower(
            "builtins.length (builtins.genList (builtins.throw \"function\") 0)",
        ))
        .expect_err("genList checks generator even for empty results");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"function");

        let ir = lower("builtins.genList (x: x) 1.2");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let length = args[1];
        let length_span = ir.arena.node(length).expect("length argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("genList length must be an integer");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: length,
                expected: "int",
                actual: ValueTag::Float,
            }
        );
        assert_eq!(error.span(), length_span);

        let ir = lower("builtins.genList (x: x) (-1)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let length = args[1];
        let length_span = ir.arena.node(length).expect("length argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("genList rejects negative lengths");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::NegativeListLength {
                id: length,
                length: -1
            }
        );
        assert_eq!(error.span(), length_span);
    }

    #[test]
    fn map_primop_builds_lazy_mapped_elements() {
        assert_eq!(
            eval("builtins.length (builtins.map (x: x + 1) [ 1 2 ])").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.map (x: x + 1) [ 1 2 ]) 0").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.map (x: x + 1) [ 1 2 ]) 1").as_int(),
            Ok(3)
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.concatStringsSep \",\" (builtins.map builtins.toString [ 1 true null ])"
            ),
            b"1,1,"
        );
        assert_eq!(
            eval("let m = builtins.map; in builtins.elemAt (m (x: x + 1) [ 1 ]) 0").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let xs = []; in builtins.length (builtins.map (builtins.throw \"function\") xs)")
                .as_int(),
            Ok(0)
        );
        assert_eq!(
            eval("let f = x: x + 1; xs = [ 1 ]; in builtins.elemAt (builtins.map f xs) 0").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.length (builtins.map (x: builtins.throw \"mapped\") [ 1 ])").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.length (builtins.map (x: x) [ (builtins.throw \"element\") ])").as_int(),
            Ok(1)
        );

        let error = eval_whnf_owned(&lower(
            "builtins.elemAt (builtins.map (x: builtins.throw \"mapped\") [ 1 ]) 0",
        ))
        .expect_err("mapped element is forced only when selected");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"mapped");

        let error = eval_whnf_owned(&lower(
            "builtins.elemAt (builtins.map (x: x) [ (builtins.throw \"element\") ]) 0",
        ))
        .expect_err("source element thunk is still lazy until selected");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"element");
    }

    #[test]
    fn map_primop_checks_list_before_function_for_nonempty_lists() {
        assert_eq!(eval("builtins.length (builtins.map 1 [])").as_int(), Ok(0));
        assert_eq!(
            eval("builtins.length (builtins.map (builtins.throw \"function\") [])").as_int(),
            Ok(0)
        );

        let ir = lower("builtins.map (builtins.throw \"function\") 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("map checks list before function");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.map (x: x) (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("map forces list argument");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.map 1 [ 2 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let function = args[0];
        let function_span = ir
            .arena
            .node(function)
            .expect("function argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("map requires a function on nonempty lists");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: function,
                expected: "function",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), function_span);
    }

    #[test]
    fn filter_primop_selects_without_forcing_returned_elements() {
        assert_eq!(
            eval("builtins.length (builtins.filter (x: x < 3) [ 1 2 3 ])").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.filter (x: x < 3) [ 1 2 3 ]) 0").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.filter (x: x < 3) [ 1 2 3 ]) 1").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.length (builtins.filter (x: false) [ (1 / 0) ])").as_int(),
            Ok(0)
        );
        assert_eq!(
            eval("builtins.length (builtins.filter (x: true) [ (1 / 0) ])").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.length (builtins.filter builtins.isInt [ 1 \"x\" 2 ])").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.elemAt (let f = builtins.filter; in f builtins.isInt [ 1 \"x\" 2 ]) 1")
                .as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let p = x: x; xs = [ true ]; in builtins.length (builtins.filter p xs)").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("let builtins = { filter = pred: list: [ 42 ]; }; in builtins.filter (x: false) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn filter_primop_checks_list_before_predicate() {
        assert_eq!(
            eval("builtins.length (builtins.filter (1 / 0) [])").as_int(),
            Ok(0)
        );
        assert_eq!(
            eval("builtins.length (builtins.filter 1 [])").as_int(),
            Ok(0)
        );
        assert_eq!(
            eval("let xs = []; in builtins.length (builtins.filter (builtins.throw \"predicate\") xs)")
                .as_int(),
            Ok(0)
        );
        assert_eq!(
            eval(
                "let f = builtins.filter; in builtins.length (f (builtins.throw \"predicate\") [])"
            )
            .as_int(),
            Ok(0)
        );
        assert_eq!(
            eval("let f = builtins.filter; in builtins.length (f 1 [])").as_int(),
            Ok(0)
        );

        let error = eval_whnf_owned(&lower(
            "let f = builtins.filter; in f (builtins.throw \"predicate\") (builtins.throw \"list\")",
        ))
        .expect_err("first-class filter checks list before predicate");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"list");

        let ir = lower("builtins.filter (1 / 0) 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("filter checks list before predicate");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.filter (x: true) (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("filter forces list argument");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: list });
        assert_eq!(error.span(), list_span);
    }

    #[test]
    fn filter_primop_checks_predicate_and_result_for_nonempty_lists() {
        let ir = lower("builtins.filter 1 [ 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let predicate = args[0];
        let predicate_span = ir
            .arena
            .node(predicate)
            .expect("predicate argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("filter requires predicate on nonempty lists");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: predicate,
                expected: "function",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), predicate_span);

        let ir = lower("builtins.filter (x: 1) [ \"a\" ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let predicate = args[0];
        let predicate_span = ir
            .arena
            .node(predicate)
            .expect("predicate argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("filter requires bool predicate result");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: predicate,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), predicate_span);
    }

    #[test]
    fn partition_primop_splits_forced_elements_into_right_and_wrong() {
        assert_eq!(
            eval_list_string_bytes("builtins.attrNames (builtins.partition (x: true) [])"),
            vec![b"right".to_vec(), b"wrong".to_vec()]
        );
        assert_eq!(
            eval("builtins.length (builtins.partition (x: x < 3) [ 1 2 3 ]).right").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).right 0").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).right 1").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.length (builtins.partition (x: x < 3) [ 1 2 3 ]).wrong").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.partition (x: x < 3) [ 1 2 3 ]).wrong 0").as_int(),
            Ok(3)
        );
        assert_eq!(
            eval("builtins.length (builtins.partition (x: true) [ { a = 1 / 0; } ]).right")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.length (builtins.partition builtins.isInt [ 1 \"x\" 2 ]).right")
                .as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("builtins.length (let f = builtins.partition; in f builtins.isInt [ 1 \"x\" 2 ]).wrong")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("let p = x: true; xs = []; in builtins.length (builtins.partition p xs).right")
                .as_int(),
            Ok(0)
        );
        assert_eq!(
            eval("let builtins = { partition = pred: list: { right = [ 42 ]; wrong = []; }; }; in builtins.partition (x: false) [] == { right = [ 42 ]; wrong = []; }")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn partition_primop_checks_predicate_before_list() {
        let ir = lower("builtins.partition (1 / 0) []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let predicate = args[0];
        let predicate_span = ir
            .arena
            .node(predicate)
            .expect("predicate argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("partition forces predicate before list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: predicate }
        );
        assert_eq!(error.span(), predicate_span);

        let ir = lower("builtins.partition 1 []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let predicate = args[0];
        let predicate_span = ir
            .arena
            .node(predicate)
            .expect("predicate argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("partition requires predicate first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: predicate,
                expected: "function",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), predicate_span);

        let ir = lower(
            "let f = builtins.partition; in f (builtins.throw \"predicate\") (builtins.throw \"list\")",
        );

        let error =
            eval_whnf_owned(&ir).expect_err("first-class partition forces predicate before list");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"predicate");

        let ir = lower("builtins.partition (x: true) 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("partition checks list after predicate");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);
    }

    #[test]
    fn partition_primop_forces_elements_before_predicate_application() {
        let ir = lower("builtins.partition (x: true) [ (1 / 0) ]");

        let error = eval_whnf_owned(&ir).expect_err("partition forces elements");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let ir = lower("builtins.partition (x: 1) [ \"a\" ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let predicate = args[0];
        let predicate_span = ir
            .arena
            .node(predicate)
            .expect("predicate argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("partition requires bool predicate result");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: predicate,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), predicate_span);
    }

    #[test]
    fn foldl_strict_primop_folds_left_and_forces_accumulator() {
        assert_eq!(
            eval("builtins.foldl' (acc: x: acc + x) 0 [ 1 2 3 ]").as_int(),
            Ok(6)
        );
        assert_eq!(
            eval("builtins.foldl' builtins.add 0 [ 1 2 3 ]").as_int(),
            Ok(6)
        );
        assert_eq!(
            eval("let f = builtins.foldl'; in f (acc: x: acc + x) 0 [ 1 2 3 ]").as_int(),
            Ok(6)
        );
        assert_eq!(
            eval("let f = builtins.foldl'; in f builtins.add 0 [ 1 2 3 ]").as_int(),
            Ok(6)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.foldl' (acc: x: acc ++ [ x ]) [] [ 1 2 3 ]) 0")
                .as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("builtins.elemAt (builtins.foldl' (acc: x: acc ++ [ x ]) [] [ 1 2 3 ]) 2")
                .as_int(),
            Ok(3)
        );
        assert_eq!(
            eval("builtins.foldl' (acc: x: acc) 0 [ (1 / 0) ]").as_int(),
            Ok(0)
        );

        let ir = lower("builtins.foldl' (acc: x: x) 0 [ (1 / 0) ]");
        let error = eval_whnf(&ir).expect_err("foldl' forces each accumulator result");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let outcome = eval_whnf_owned(&lower("builtins.foldl' (acc: x: { a = 1 / 0; }) 0 [ 1 ]"))
            .expect("foldl' forces accumulator to WHNF only");
        assert_eq!(outcome.value().tag(), ValueTag::Attrs);
    }

    #[test]
    fn foldl_strict_primop_checks_operator_then_list_then_initial() {
        let ir = lower("builtins.foldl' (1 / 0) 0 []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let op = args[0];
        let op_span = ir.arena.node(op).expect("operator argument exists").span;

        let error = eval_whnf(&ir).expect_err("foldl' forces operator first");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: op });
        assert_eq!(error.span(), op_span);

        let ir = lower("builtins.foldl' 1 0 []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let op = args[0];
        let op_span = ir.arena.node(op).expect("operator argument exists").span;

        let error = eval_whnf(&ir).expect_err("foldl' requires an operator function");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: op,
                expected: "function",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), op_span);

        let ir = lower("builtins.foldl' (acc: x: acc) (1 / 0) 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[2];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf(&ir).expect_err("foldl' checks list before initial value");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.foldl' (acc: x: acc) (1 / 0) []");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let initial = args[1];
        let initial_span = ir
            .arena
            .node(initial)
            .expect("initial argument exists")
            .span;

        let error = eval_whnf(&ir).expect_err("foldl' forces initial value after list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: initial }
        );
        assert_eq!(error.span(), initial_span);

        let error = eval_whnf_owned(&lower("let f = builtins.foldl'; in f (1 / 0) 0 []"))
            .expect_err("first-class foldl' forces operator first");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let error = eval_whnf_owned(&lower("let f = builtins.foldl'; in f 1 0 []"))
            .expect_err("first-class foldl' requires an operator function");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "function",
                actual: ValueTag::Int,
                ..
            }
        ));

        let error = eval_whnf_owned(&lower(
            "let f = builtins.foldl'; in f (acc: x: acc) (1 / 0) 1",
        ))
        .expect_err("first-class foldl' checks list before initial value");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Int,
                ..
            }
        ));

        let error = eval_whnf_owned(&lower(
            "let f = builtins.foldl'; in f (acc: x: acc) (1 / 0) []",
        ))
        .expect_err("first-class foldl' forces initial after list");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn foldl_strict_primop_checks_curried_operator_results() {
        let ir = lower("builtins.foldl' (acc: 1) 0 [ 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let op = args[0];
        let op_span = ir.arena.node(op).expect("operator argument exists").span;

        let error = eval_whnf(&ir).expect_err("foldl' requires curried binary operator");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: op,
                expected: "lambda",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), op_span);

        assert_eq!(
            eval("let builtins = { foldl' = op: initial: list: 42; }; in builtins.foldl' (acc: x: acc) 0 []")
                .as_int(),
            Ok(42)
        );
    }

    #[test]
    fn sort_primop_orders_stably_with_comparator() {
        assert_eq!(
            eval_list_ints("builtins.sort builtins.lessThan [ 3 1 2 1 ]"),
            vec![1, 1, 2, 3]
        );
        assert_eq!(
            eval_list_ints("builtins.sort (a: b: builtins.lessThan b a) [ 3 1 2 ]"),
            vec![3, 2, 1]
        );
        assert_eq!(
            eval_list_ints("let sort = builtins.sort builtins.lessThan; in sort [ 3 1 2 ]"),
            vec![1, 2, 3]
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.concatStringsSep \",\" (builtins.map (x: x.name) (builtins.sort (a: b: a.key < b.key) [ { key = 1; name = \"a\"; } { key = 1; name = \"b\"; } { key = 0; name = \"c\"; } ]))"
            ),
            b"c,a,b"
        );
        assert_eq!(
            eval("let builtins = { sort = comparator: list: [ 42 ]; }; in builtins.sort (a: b: false) [] == [ 42 ]")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn sort_primop_checks_comparator_list_and_result_types() {
        assert_eq!(
            eval_list_ints("builtins.sort (1 / 0) []"),
            Vec::<i64>::new()
        );
        assert_eq!(eval_list_ints("builtins.sort 1 []"), Vec::<i64>::new());
        assert_eq!(
            eval_list_ints("let sort = builtins.sort 1; in sort []"),
            Vec::<i64>::new()
        );

        let ir = lower("builtins.sort (1 / 0) 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;
        let error = eval_whnf_owned(&ir).expect_err("sort checks the list before comparator");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.sort 1 [ 1 ]");
        let error = eval_whnf_owned(&ir).expect_err("sort requires a comparator function");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "function",
                actual: ValueTag::Int,
                ..
            }
        ));

        let ir = lower("let sort = builtins.sort; in sort 1 []");
        let result =
            eval_whnf_owned(&ir).expect("first-class sort skips comparator for empty list");
        let list = result
            .heap()
            .get_list(result.value())
            .expect("result is a list");
        assert!(list.is_empty());

        let ir = lower(
            "let sort = builtins.sort; in sort (builtins.throw \"comparator\") (builtins.throw \"list\")",
        );
        let error =
            eval_whnf_owned(&ir).expect_err("first-class sort forces list before comparator");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"list");

        let ir = lower("builtins.sort (a: b: false) 1");
        let error = eval_whnf_owned(&ir).expect_err("sort requires a list");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "list",
                actual: ValueTag::Int,
                ..
            }
        ));

        let ir = lower("builtins.sort (a: b: 1) [ 1 2 ]");
        let error = eval_whnf_owned(&ir).expect_err("sort comparator must return bool");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "bool",
                actual: ValueTag::Int,
                ..
            }
        ));

        let ir = lower("builtins.sort (a: b: false) [ (1 / 0) true ]");
        let error = eval_whnf_owned(&ir).expect_err("sort forces elements before comparison");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let ir = lower("builtins.sort 1 [ (1 / 0) ]");
        let error = eval_whnf_owned(&ir).expect_err("sort validates comparator before elements");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "function",
                actual: ValueTag::Int,
                ..
            }
        ));

        let ir = lower("builtins.sort builtins.lessThan [ 1 (1 / 0) ]");
        let error = eval_whnf_owned(&ir).expect_err("sort forces elements");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn sort_primop_matches_libcxx_small_range_comparator_order() {
        let ir = lower(
            "builtins.sort (a: b:
              if a == 2 && b == 1 then builtins.throw \"wrong-order\"
              else if a == 2 && b == 3 then builtins.throw \"2<3\"
              else a < b)
            [ 3 1 2 ]",
        );
        let error =
            eval_whnf_owned(&ir).expect_err("sort reaches the libc++ second comparison first");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"2<3");
    }

    #[test]
    fn sort_primop_matches_libcxx_large_range_merge_order() {
        // libc++ insertion-sorts pointer-like values up to 128 elements; 129
        // elements reaches the recursive stable-sort merge path. C++ Nix
        // 2.24 observes this top-level merge comparison for the descending fixture.
        let ir = lower(
            "builtins.sort (a: b:
              if a == 1 && b == 66 then builtins.throw \"top-merge\"
              else a < b)
            (builtins.genList (i: 129 - i) 129)",
        );
        let error =
            eval_whnf_owned(&ir).expect_err("sort reaches the libc++ large-range merge path");
        let TreeWalkErrorKind::Thrown { message, .. } = error.kind() else {
            panic!("expected thrown error");
        };
        assert_eq!(message, b"top-merge");
    }

    #[test]
    fn less_than_primop_uses_language_comparison_semantics() {
        assert_eq!(eval("builtins.lessThan 1 2").as_bool(), Ok(true));
        assert_eq!(eval("builtins.lessThan 2 1").as_bool(), Ok(false));
        assert_eq!(eval("builtins.lessThan 1 1").as_bool(), Ok(false));
        assert_eq!(eval("builtins.lessThan 1 1.5").as_bool(), Ok(true));
        assert_eq!(eval("builtins.lessThan \"a\" \"b\"").as_bool(), Ok(true));
        assert_eq!(
            eval("builtins.lessThan [ 1 2 ] [ 1 3 ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.lessThan [ 1 (1 / 0) ] [ 2 (1 / 0) ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let builtins = { lessThan = left: right: false; }; in builtins.lessThan 1 2")
                .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn less_than_primop_forces_operands_before_type_checks() {
        let ir = lower("builtins.lessThan true (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("lessThan forces rhs before type check");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let ir = lower("builtins.lessThan true false");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let lhs = args[0];
        let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&ir).expect_err("lessThan rejects incomparable lhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "number, string, or list",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), lhs_span);

        let ir = lower("builtins.lessThan 1 true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("lessThan checks rhs against lhs type");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::Bool
            }
        );
        assert_eq!(error.span(), rhs_span);

        let ir = lower("builtins.lessThan [ 1 (1 / 0) ] [ 1 2 ]");
        let error = eval_whnf_owned(&ir).expect_err("equal list prefix forces next element");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn arithmetic_primops_use_numeric_semantics() {
        assert_eq!(eval("builtins.add 1 2").as_int(), Ok(3));
        assert_eq!(eval("builtins.sub 5 8").as_int(), Ok(-3));
        assert_eq!(eval("builtins.mul 2 3").as_int(), Ok(6));
        assert_eq!(eval("builtins.div 7 2").as_int(), Ok(3));
        assert_eq!(eval("builtins.add 1 2.5").as_float(), Ok(3.5));
        assert_eq!(eval("builtins.sub 1 2.5").as_float(), Ok(-1.5));
        assert_eq!(eval("builtins.mul 2 0.5").as_float(), Ok(1.0));
        assert_eq!(eval("builtins.div 7 2.0").as_float(), Ok(3.5));
        assert_eq!(
            eval("builtins.add 9223372036854775807 1").as_int(),
            Ok(i64::MIN)
        );
        assert_eq!(eval("builtins.mul 9223372036854775807 2").as_int(), Ok(-2));
    }

    #[test]
    fn arithmetic_primops_are_strict_and_numeric_only() {
        let ir = lower("builtins.add \"a\" (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("rhs evaluation error wins before type check");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let ir = lower("builtins.add \"a\" \"b\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let lhs = args[0];
        let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("strings are invalid for builtins.add");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "number",
                actual: ValueTag::String,
            }
        );
        assert_eq!(error.span(), lhs_span);

        let ir = lower("builtins.sub true (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("sub forces rhs before lhs type check");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let div_zero = lower("builtins.div 1 0");
        let error = eval_whnf(&div_zero).expect_err("integer division by zero is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: div_zero.root }
        );

        let div_overflow = lower("builtins.div (-9223372036854775807 - 1) (-1)");
        let error = eval_whnf(&div_overflow).expect_err("integer division overflow is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ArithmeticOverflow {
                id: div_overflow.root,
                op: ArithmeticOp::Div,
            }
        );
    }

    #[test]
    fn bitwise_primops_apply_signed_integer_ops() {
        assert_eq!(eval("builtins.bitAnd 6 3").as_int(), Ok(2));
        assert_eq!(eval("builtins.bitOr 4 1").as_int(), Ok(5));
        assert_eq!(eval("builtins.bitXor 6 3").as_int(), Ok(5));
        assert_eq!(eval("builtins.bitXor (-1) 1").as_int(), Ok(-2));
        assert_eq!(
            eval("let builtins = { bitAnd = left: right: 42; }; in builtins.bitAnd 6 3").as_int(),
            Ok(42)
        );
    }

    #[test]
    fn bitwise_primops_type_check_arguments_left_to_right() {
        let ir = lower("builtins.bitAnd true (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let lhs = args[0];
        let lhs_span = ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&ir).expect_err("bitAnd checks lhs before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "int",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), lhs_span);

        let ir = lower("builtins.bitAnd 1 true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("bitAnd checks rhs after valid lhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "int",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let ir = lower("builtins.bitAnd 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let rhs = args[1];
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("bitAnd forces rhs after valid lhs");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn get_attr_primop_returns_attr_without_forcing_selected_value() {
        assert_eq!(
            eval("builtins.getAttr \"a\" { a = 1; b = 1 / 0; }").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("let builtins = { getAttr = name: set: 42; }; in builtins.getAttr \"a\" {}")
                .as_int(),
            Ok(42)
        );

        let ir = lower("builtins.getAttr \"a\" { a = 1 / 0; }");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("getAttr primop evaluates");
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("selected attr remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn get_attr_primop_reports_missing_attrs() {
        let ir = lower("builtins.getAttr \"missing\" { a = 1; }");
        let root = ir.arena.node(ir.root).expect("root exists");

        let error = eval_whnf(&ir).expect_err("getAttr requires the attribute to exist");

        let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
            panic!("expected a missing attribute error");
        };
        assert_eq!(id, ir.root);
        assert_eq!(ir.symbols.resolve(symbol), Some(b"missing".as_slice()));
        assert_eq!(error.span(), root.span);
    }

    #[test]
    fn get_attr_primop_type_checks_arguments_in_order() {
        let ir = lower("builtins.getAttr 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let name = args[0];
        let name_span = ir.arena.node(name).expect("name argument exists").span;

        let error = eval_whnf(&ir).expect_err("getAttr checks the name before the attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: name,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), name_span);

        let ir = lower("builtins.getAttr \"a\" 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let attrs = args[1];
        let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

        let error = eval_whnf(&ir).expect_err("getAttr requires an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: attrs,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), attrs_span);
    }

    #[test]
    fn has_attr_primop_reports_presence_without_forcing_values() {
        assert_eq!(
            eval("builtins.hasAttr \"a\" { a = 1 / 0; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("builtins.hasAttr \"b\" { a = 1 / 0; }").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let builtins = { hasAttr = name: set: false; }; in builtins.hasAttr \"a\" { a = true; }")
                .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn has_attr_primop_type_checks_name_before_attrset() {
        let ir = lower("builtins.hasAttr 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let name = args[0];
        let name_span = ir.arena.node(name).expect("name argument exists").span;

        let error = eval_whnf(&ir).expect_err("hasAttr checks the name before the attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: name,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), name_span);

        let ir = lower("builtins.hasAttr \"a\" 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let attrs = args[1];
        let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

        let error = eval_whnf(&ir).expect_err("hasAttr requires an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: attrs,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), attrs_span);
    }

    #[test]
    fn remove_attrs_primop_removes_names_without_forcing_values() {
        assert_eq!(
            eval_list_string_bytes(
                "builtins.attrNames (builtins.removeAttrs { z = 1; a = 1 / 0; b = 2; } [ \"z\" \"missing\" \"z\" ])"
            ),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        assert_eq!(
            eval("let r = builtins.removeAttrs { a = 1 / 0; b = 2; } [ \"a\" ]; in r.b").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let builtins = { removeAttrs = set: names: { local = true; }; }; in (builtins.removeAttrs {} []).local")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn remove_attrs_primop_type_checks_arguments_in_order() {
        let ir = lower("builtins.removeAttrs 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let attrs = args[0];
        let attrs_span = ir.arena.node(attrs).expect("attrset argument exists").span;

        let error = eval_whnf(&ir).expect_err("removeAttrs checks the attrset before names");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: attrs,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), attrs_span);

        let ir = lower("builtins.removeAttrs {} 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let names = args[1];
        let names_span = ir.arena.node(names).expect("names argument exists").span;

        let error = eval_whnf(&ir).expect_err("removeAttrs requires a name list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: names,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), names_span);

        let ir = lower("builtins.removeAttrs {} [ 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let names = args[1];
        let names_span = ir.arena.node(names).expect("names argument exists").span;

        let error = eval_whnf(&ir).expect_err("removeAttrs requires string names");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: names,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), names_span);
    }

    #[test]
    fn intersect_attrs_primop_takes_names_from_left_and_values_from_right() {
        assert_eq!(
            eval_list_string_bytes(
                "builtins.attrNames (builtins.intersectAttrs { z = 1; a = 1 / 0; b = 3; } { z = 4; a = 5; c = 6; })"
            ),
            vec![b"a".to_vec(), b"z".to_vec()]
        );
        assert_eq!(
            eval("let r = builtins.intersectAttrs { a = 1 / 0; } { a = 2; }; in r.a").as_int(),
            Ok(2)
        );
        assert_eq!(
            eval("let builtins = { intersectAttrs = left: right: { local = true; }; }; in (builtins.intersectAttrs {} {}).local")
                .as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.intersectAttrs { a = 1; } { a = 1 / 0; }");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("intersectAttrs primop evaluates");
        let attrs = evaluator
            .heap
            .get_attrs(value)
            .expect("intersectAttrs result is attrs");
        let entry = attrs
            .iter_lexicographic()
            .next()
            .expect("intersectAttrs result has one attr");
        assert_eq!(ir.symbols.resolve(entry.key), Some(b"a".as_slice()));
        let value = entry.value;
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("selected right value remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn intersect_attrs_primop_type_checks_arguments_in_order() {
        let ir = lower("builtins.intersectAttrs 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let left = args[0];
        let left_span = ir.arena.node(left).expect("left argument exists").span;

        let error = eval_whnf(&ir).expect_err("intersectAttrs checks the left set first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: left,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), left_span);

        let ir = lower("builtins.intersectAttrs {} 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let right = args[1];
        let right_span = ir.arena.node(right).expect("right argument exists").span;

        let error = eval_whnf(&ir).expect_err("intersectAttrs requires a right attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: right,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), right_span);
    }

    #[test]
    fn cat_attrs_primop_collects_present_attrs_in_list_order() {
        let outcome = eval_whnf_owned(&lower(
            "builtins.catAttrs \"a\" [ { a = 1; } { b = 1 / 0; } { a = 2; } ]",
        ))
        .expect("catAttrs evaluates");
        let list = outcome
            .heap()
            .get_list(outcome.value())
            .expect("catAttrs returns a list");

        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).expect("first").as_int(), Ok(1));
        assert_eq!(list.get(1).expect("second").as_int(), Ok(2));
        let shadowed = eval_whnf_owned(&lower(
            "let builtins = { catAttrs = name: list: [ true ]; }; in builtins.catAttrs \"a\" []",
        ))
        .expect("shadowed catAttrs evaluates");
        let shadowed_list = shadowed
            .heap()
            .get_list(shadowed.value())
            .expect("shadowed catAttrs returns a list");
        assert_eq!(
            shadowed_list.get(0).expect("first local value").as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.catAttrs \"a\" [ { a = 1 / 0; } { b = 2; } ]");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_primop(ir.root, &root)
            .expect("catAttrs primop evaluates");
        let list = evaluator
            .heap
            .get_list(value)
            .expect("catAttrs returns a heap-owned list");
        assert_eq!(list.len(), 1);
        let value = list.get(0).expect("selected attr exists");
        assert_eq!(value.tag(), ValueTag::Thunk);
        let thunk = evaluator
            .heap
            .get_thunk(value)
            .expect("selected attr value remains a heap-owned thunk");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn cat_attrs_primop_type_checks_arguments_and_elements_in_order() {
        let ir = lower("builtins.catAttrs 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let name = args[0];
        let name_span = ir.arena.node(name).expect("name argument exists").span;

        let error = eval_whnf(&ir).expect_err("catAttrs checks the name before the list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: name,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), name_span);

        let ir = lower("builtins.catAttrs \"a\" 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf(&ir).expect_err("catAttrs requires a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.catAttrs \"a\" [ 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("catAttrs requires attrset elements");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "attrs",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), list_span);
    }

    #[test]
    fn ceil_and_floor_primops_round_numbers_to_ints() {
        assert_eq!(eval("builtins.ceil 1").as_int(), Ok(1));
        assert_eq!(eval("builtins.ceil 1.2").as_int(), Ok(2));
        assert_eq!(eval("builtins.ceil (-1.2)").as_int(), Ok(-1));
        assert_eq!(eval("builtins.floor 1").as_int(), Ok(1));
        assert_eq!(eval("builtins.floor 1.8").as_int(), Ok(1));
        assert_eq!(eval("builtins.floor (-1.2)").as_int(), Ok(-2));
        assert_eq!(
            eval("let builtins = { ceil = x: 42; }; in builtins.ceil 1.2").as_int(),
            Ok(42)
        );
        assert_eq!(
            eval("let builtins = { floor = x: 42; }; in builtins.floor 1.8").as_int(),
            Ok(42)
        );
    }

    #[test]
    fn ceil_and_floor_primops_type_check_arguments() {
        for source in ["builtins.ceil true", "builtins.floor true"] {
            let ir = lower(source);
            let root = ir.arena.node(ir.root).expect("root exists");
            let IrData::PrimOp { args, .. } = root.data else {
                panic!("root is a primop");
            };
            let args = ir.arena.child_slice(args).expect("primop args exist");
            let argument = args[0];
            let argument_span = ir.arena.node(argument).expect("argument exists").span;

            let error = eval_whnf(&ir).expect_err("rounding requires a number");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "number",
                    actual: ValueTag::Bool
                }
            );
            assert_eq!(error.span(), argument_span);
        }
    }

    #[test]
    fn ceil_and_floor_primops_saturate_int_range_boundaries() {
        for source in [
            "builtins.ceil 9223372036854775807.0",
            "builtins.ceil 9223372036854775808.0",
            "builtins.floor 9223372036854775807.0",
            "builtins.floor 9223372036854775808.0",
        ] {
            assert_eq!(eval(source).as_int(), Ok(i64::MAX));
        }
    }

    #[test]
    fn seq_primop_forces_first_to_whnf_and_returns_second() {
        assert_eq!(eval("builtins.seq { x = 1 / 0; } 2").as_int(), Ok(2));
        assert_eq!(
            eval("builtins.length (builtins.seq 1 [ (1 / 0) ])").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("let builtins = { seq = first: second: 42; }; in builtins.seq (1 / 0) 0").as_int(),
            Ok(42)
        );
    }

    #[test]
    fn seq_primop_reports_forcing_errors_left_to_right() {
        let ir = lower("builtins.seq (1 / 0) 2");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let first = args[0];
        let first_span = ir.arena.node(first).expect("first argument exists").span;

        let error = eval_whnf(&ir).expect_err("seq forces first argument first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: first }
        );
        assert_eq!(error.span(), first_span);

        let ir = lower("builtins.seq 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let second = args[1];
        let IrData::Node(second_body) = ir.arena.node(second).expect("second argument exists").data
        else {
            panic!("second argument is a thunk allocation");
        };
        let second_span = ir
            .arena
            .node(second_body)
            .expect("second thunk body exists")
            .span;

        let error = eval_whnf(&ir).expect_err("seq returns and demands second argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: second_body }
        );
        assert_eq!(error.span(), second_span);
    }

    #[test]
    fn deep_seq_primop_forces_nested_values_and_returns_second() {
        assert_eq!(eval("builtins.deepSeq [ 1 [ 2 ] ] 3").as_int(), Ok(3));
        assert_eq!(
            eval("builtins.deepSeq { a = { b = 1; }; } 3").as_int(),
            Ok(3)
        );
        assert_eq!(eval("builtins.deepSeq (x: x) 3").as_int(), Ok(3));
        assert_eq!(
            eval("let x = { a = x; }; in builtins.deepSeq x 3").as_int(),
            Ok(3)
        );
        assert_eq!(
            eval(
                "let builtins = { deepSeq = first: second: 42; }; in builtins.deepSeq [ (1 / 0) ] 0"
            )
            .as_int(),
            Ok(42)
        );
    }

    #[test]
    fn deep_seq_primop_reports_nested_forcing_errors_before_second() {
        let ir = lower("builtins.deepSeq [ (1 / 0) ] (2 / 0)");
        let error = eval_whnf(&ir).expect_err("deepSeq forces list elements first");
        let TreeWalkErrorKind::DivisionByZero { id: first } = error.kind() else {
            panic!("expected first list element division by zero");
        };
        let first_span = ir.arena.node(first).expect("first error node exists").span;
        assert_eq!(error.span(), first_span);

        let ir = lower("builtins.deepSeq { a = 1 / 0; } 2");
        let error = eval_whnf(&ir).expect_err("deepSeq forces attr values");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let source = "builtins.deepSeq { z = 1 / 0; a = 2 / 0; } 1";
        let ir = lower(source);
        let error = eval_whnf(&ir).expect_err("deepSeq forces attr values in source order");
        let z_error_start = source.find("1 / 0").expect("z error expression exists") as u32;
        assert_eq!(
            error.span(),
            Span::new(z_error_start, z_error_start + "1 / 0".len() as u32)
        );

        let ir = lower("builtins.deepSeq [ 1 ] (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let second = args[1];
        let IrData::Node(second_body) = ir.arena.node(second).expect("second argument exists").data
        else {
            panic!("second argument is a thunk allocation");
        };
        let second_span = ir
            .arena
            .node(second_body)
            .expect("second thunk body exists")
            .span;

        let error = eval_whnf(&ir).expect_err("deepSeq returns and demands second argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: second_body }
        );
        assert_eq!(error.span(), second_span);
    }

    #[test]
    fn has_context_primop_reports_string_context_presence() {
        assert_eq!(eval("builtins.hasContext \"x\"").as_bool(), Ok(false));
        assert_eq!(
            eval("let builtins = { hasContext = x: true; }; in builtins.hasContext \"x\"")
                .as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.hasContext \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("hasContext argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"x".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing string allocates");

        assert_eq!(
            evaluator
                .eval_has_context_primop(argument, argument_span, value)
                .expect("hasContext evaluates")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn has_context_primop_type_checks_argument() {
        let ir = lower("builtins.hasContext 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("hasContext requires a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn get_context_primop_reflects_sparse_context_attrs() {
        assert_eq!(
            eval_list_string_bytes("builtins.attrNames (builtins.getContext \"x\")"),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(
            eval("let builtins = { getContext = x: { local = true; }; }; in (builtins.getContext \"x\").local")
                .as_bool(),
            Ok(true)
        );

        let ir = lower("builtins.getContext \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("getContext argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source_path = b"/nix/store/source";
        let drv_path = b"/nix/store/derivation.drv";
        let deep_path = b"/nix/store/deep.drv";
        let context = StringContext::new(vec![
            ContextElement::single_output(drv_path.to_vec(), b"out".to_vec())
                .expect("output context is valid"),
            ContextElement::opaque_path(source_path.to_vec()).expect("source context is valid"),
            ContextElement::deep_derivation(deep_path.to_vec()).expect("deep context is valid"),
            ContextElement::single_output(drv_path.to_vec(), b"dev".to_vec())
                .expect("output context is valid"),
        ]);
        let value = evaluator
            .heap
            .alloc_string(NixString::new(b"x".to_vec(), context))
            .expect("context-bearing string allocates");

        let result = evaluator
            .eval_get_context_primop(ir.root, root.span, argument, argument_span, value)
            .expect("getContext evaluates");

        let source_key = evaluator
            .symbols
            .intern(source_path)
            .expect("source key interns");
        let drv_key = evaluator.symbols.intern(drv_path).expect("drv key interns");
        let deep_key = evaluator
            .symbols
            .intern(deep_path)
            .expect("deep key interns");
        let path_key = evaluator.symbols.intern(b"path").expect("path key interns");
        let outputs_key = evaluator
            .symbols
            .intern(b"outputs")
            .expect("outputs key interns");
        let all_outputs_key = evaluator
            .symbols
            .intern(b"allOutputs")
            .expect("allOutputs key interns");
        let top = evaluator
            .heap
            .get_attrs(result)
            .expect("getContext returns attrs");

        let source = evaluator
            .heap
            .get_attrs(top.get(source_key).expect("source context exists"))
            .expect("source context value is attrs");
        assert_eq!(
            source
                .get(path_key)
                .expect("opaque path marker exists")
                .as_bool(),
            Ok(true)
        );
        assert!(source.get(outputs_key).is_none());
        assert!(source.get(all_outputs_key).is_none());

        let drv = evaluator
            .heap
            .get_attrs(top.get(drv_key).expect("drv context exists"))
            .expect("drv context value is attrs");
        assert!(drv.get(path_key).is_none());
        assert!(drv.get(all_outputs_key).is_none());
        let outputs = evaluator
            .heap
            .get_list(drv.get(outputs_key).expect("outputs marker exists"))
            .expect("outputs marker is a list");
        assert_eq!(outputs.len(), 2);
        assert_eq!(
            evaluator
                .heap
                .get_string(outputs.get(0).expect("first output"))
                .expect("first output is a string")
                .bytes(),
            b"dev"
        );
        assert_eq!(
            evaluator
                .heap
                .get_string(outputs.get(1).expect("second output"))
                .expect("second output is a string")
                .bytes(),
            b"out"
        );

        let deep = evaluator
            .heap
            .get_attrs(top.get(deep_key).expect("deep context exists"))
            .expect("deep context value is attrs");
        assert!(deep.get(path_key).is_none());
        assert!(deep.get(outputs_key).is_none());
        assert_eq!(
            deep.get(all_outputs_key)
                .expect("deep marker exists")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn get_context_primop_type_checks_argument() {
        let ir = lower("builtins.getContext 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("getContext requires a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn add_drv_output_dependencies_primop_upgrades_derivation_context() {
        assert_eq!(
            eval_string_bytes(
                "let builtins = { addDrvOutputDependencies = value: \"shadow\"; }; in builtins.addDrvOutputDependencies \"x\""
            ),
            b"shadow"
        );

        let ir = lower("builtins.addDrvOutputDependencies \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("addDrvOutputDependencies argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let drv_path = b"/nix/store/derivation.drv";
        let context = StringContext::singleton(
            ContextElement::opaque_path(drv_path.to_vec()).expect("drv context is valid"),
        )
        .expect("context allocates");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(drv_path.to_vec(), context))
            .expect("context-bearing string allocates");

        let result = evaluator
            .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
            .expect("addDrvOutputDependencies evaluates");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result string exists");

        assert_eq!(string.bytes(), drv_path);
        assert_eq!(string.context().len(), 1);
        let element = string
            .context()
            .elements()
            .first()
            .expect("result context element exists");
        assert_eq!(element.kind(), ContextKind::DeepDerivation);
        assert_eq!(element.path(), drv_path);
    }

    #[test]
    fn add_drv_output_dependencies_primop_is_idempotent_for_deep_context() {
        let ir = lower("builtins.addDrvOutputDependencies \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("addDrvOutputDependencies argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let drv_path = b"/nix/store/deep.drv";
        let context = StringContext::singleton(
            ContextElement::deep_derivation(drv_path.to_vec()).expect("deep context is valid"),
        )
        .expect("context allocates");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(drv_path.to_vec(), context))
            .expect("context-bearing string allocates");

        let result = evaluator
            .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
            .expect("addDrvOutputDependencies evaluates");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result string exists");

        assert_eq!(string.bytes(), drv_path);
        assert_eq!(string.context().len(), 1);
        let element = string
            .context()
            .elements()
            .first()
            .expect("result context element exists");
        assert_eq!(element.kind(), ContextKind::DeepDerivation);
        assert_eq!(element.path(), drv_path);
    }

    #[test]
    fn add_drv_output_dependencies_primop_rejects_invalid_context_shapes() {
        let ir = lower("builtins.addDrvOutputDependencies \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("addDrvOutputDependencies argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("empty context is rejected");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextElementCount {
                id: argument,
                len: 0,
            }
        );
        assert_eq!(error.span(), argument_span);

        let mut evaluator = TreeWalk::new(&ir);
        let context = StringContext::new(vec![
            ContextElement::opaque_path(b"/nix/store/a.drv".to_vec())
                .expect("first context is valid"),
            ContextElement::opaque_path(b"/nix/store/b.drv".to_vec())
                .expect("second context is valid"),
        ]);
        let value = evaluator
            .heap
            .alloc_string(NixString::new(b"x".to_vec(), context))
            .expect("context-bearing string allocates");
        let error = evaluator
            .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
            .expect_err("multiple context elements are rejected");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextElementCount {
                id: argument,
                len: 2,
            }
        );

        let mut evaluator = TreeWalk::new(&ir);
        let source_path = b"/nix/store/source";
        let context = StringContext::singleton(
            ContextElement::opaque_path(source_path.to_vec()).expect("source context is valid"),
        )
        .expect("context allocates");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(source_path.to_vec(), context))
            .expect("context-bearing string allocates");
        let error = evaluator
            .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
            .expect_err("non-derivation context paths are rejected");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextPathNotDerivation {
                id: argument,
                path: source_path.to_vec(),
            }
        );

        let mut evaluator = TreeWalk::new(&ir);
        let drv_path = b"/nix/store/output.drv";
        let context = StringContext::singleton(
            ContextElement::single_output(drv_path.to_vec(), b"out".to_vec())
                .expect("output context is valid"),
        )
        .expect("context allocates");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(drv_path.to_vec(), context))
            .expect("context-bearing string allocates");
        let error = evaluator
            .eval_add_drv_output_dependencies_primop(argument, argument_span, value)
            .expect_err("output context is rejected");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextDerivationOutput {
                id: argument,
                output: b"out".to_vec(),
            }
        );
    }

    #[test]
    fn add_drv_output_dependencies_primop_coerces_argument() {
        let ir = lower("builtins.addDrvOutputDependencies 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("integer coercion is rejected");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.addDrvOutputDependencies { outPath = \"x\"; }");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("coerced context-free string is rejected");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextElementCount {
                id: argument,
                len: 0,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn unsafe_discard_output_dependency_primop_downgrades_deep_contexts() {
        assert_eq!(
            eval_string_bytes("builtins.unsafeDiscardOutputDependency \"abc\""),
            b"abc"
        );
        assert_eq!(
            eval_string_bytes("builtins.unsafeDiscardOutputDependency { outPath = \"abc\"; }"),
            b"abc"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { unsafeDiscardOutputDependency = value: \"shadow\"; }; in builtins.unsafeDiscardOutputDependency \"abc\""
            ),
            b"shadow"
        );

        let ir = lower("builtins.unsafeDiscardOutputDependency \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("unsafeDiscardOutputDependency argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source_path = b"/nix/store/source";
        let deep_path = b"/nix/store/deep.drv";
        let output_path = b"/nix/store/output.drv";
        let context = StringContext::new(vec![
            ContextElement::deep_derivation(deep_path.to_vec()).expect("deep context is valid"),
            ContextElement::opaque_path(deep_path.to_vec()).expect("opaque context is valid"),
            ContextElement::opaque_path(source_path.to_vec()).expect("source context is valid"),
            ContextElement::single_output(output_path.to_vec(), b"out".to_vec())
                .expect("output context is valid"),
        ]);
        let value = evaluator
            .heap
            .alloc_string(NixString::new(b"x".to_vec(), context))
            .expect("context-bearing string allocates");

        let result = evaluator
            .eval_unsafe_discard_output_dependency_primop(argument, argument_span, value)
            .expect("unsafeDiscardOutputDependency evaluates");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result string exists");

        assert_eq!(string.bytes(), b"x");
        assert_eq!(string.context().len(), 3);
        assert!(string.context().contains(
            &ContextElement::opaque_path(source_path.to_vec()).expect("source context builds")
        ));
        assert!(string.context().contains(
            &ContextElement::opaque_path(deep_path.to_vec()).expect("deep path context builds")
        ));
        assert!(
            string.context().contains(
                &ContextElement::single_output(output_path.to_vec(), b"out".to_vec())
                    .expect("output context builds")
            )
        );
        assert!(!string.context().contains(
            &ContextElement::deep_derivation(deep_path.to_vec()).expect("deep context builds")
        ));
    }

    #[test]
    fn unsafe_discard_output_dependency_primop_coerces_argument() {
        let ir = lower("builtins.unsafeDiscardOutputDependency 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("integer coercion is rejected");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn unsafe_discard_string_context_primop_returns_context_free_string() {
        assert_eq!(
            eval_string_bytes("builtins.unsafeDiscardStringContext \"abc\""),
            b"abc"
        );
        assert_eq!(
            eval_string_bytes("builtins.unsafeDiscardStringContext { outPath = \"abc\"; }"),
            b"abc"
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.unsafeDiscardStringContext { __toString = self: \"custom\"; }"
            ),
            b"custom"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { unsafeDiscardStringContext = value: \"shadow\"; }; in builtins.unsafeDiscardStringContext \"abc\""
            ),
            b"shadow"
        );

        let ir = lower("builtins.unsafeDiscardStringContext \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("unsafeDiscardStringContext argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"x".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing string allocates");

        let result = evaluator
            .eval_unsafe_discard_string_context_primop(argument, argument_span, value)
            .expect("unsafeDiscardStringContext evaluates");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result string exists");

        assert_eq!(string.bytes(), b"x");
        assert!(!string.has_context());
    }

    #[test]
    fn unsafe_discard_string_context_primop_forces_and_coerces_argument() {
        let ir = lower("builtins.unsafeDiscardStringContext (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("unsafeDiscardStringContext forces its argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.unsafeDiscardStringContext 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("integer is not string-coercible here");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn string_length_primop_counts_coerced_string_bytes() {
        assert_eq!(eval("builtins.stringLength \"abc\"").as_int(), Ok(3));
        assert_eq!(eval("builtins.stringLength \"a\\n\"").as_int(), Ok(2));
        assert_eq!(
            eval("builtins.stringLength { outPath = \"abc\"; }").as_int(),
            Ok(3)
        );
        assert_eq!(
            eval("builtins.stringLength { __toString = self: self.name; name = \"custom\"; }")
                .as_int(),
            Ok(6)
        );
        assert_eq!(
            eval("let builtins = { stringLength = value: 42; }; in builtins.stringLength \"abc\"")
                .as_int(),
            Ok(42)
        );
    }

    #[test]
    fn string_length_primop_forces_and_coerces_argument() {
        let ir = lower("builtins.stringLength (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("stringLength forces its argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.stringLength 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("integer is not string-coercible here");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn replace_strings_primop_replaces_bytes() {
        assert_eq!(
            eval_string_bytes(
                "builtins.replaceStrings [ \"o\" \"l\" ] [ \"0\" \"L\" ] \"hello world\""
            ),
            b"heLL0 w0rLd"
        );
        assert_eq!(
            eval_string_bytes("builtins.replaceStrings [ \"\" ] [ \"x\" ] \"ab\""),
            b"xaxbx"
        );
        assert_eq!(
            eval_string_bytes("builtins.replaceStrings [ \"a\" \"ab\" ] [ \"X\" \"Y\" ] \"ababa\""),
            b"XbXbX"
        );
        assert_eq!(
            eval_string_bytes("builtins.replaceStrings [ \"ab\" \"a\" ] [ \"Y\" \"X\" ] \"ababa\""),
            b"YYX"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { replaceStrings = from: to: string: \"local\"; }; in builtins.replaceStrings [ \"a\" ] [ \"b\" ] \"a\""
            ),
            b"local"
        );
    }

    #[test]
    fn replace_strings_primop_checks_lengths_before_elements() {
        let ir = lower("builtins.replaceStrings [ (1 / 0) ] [] (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");

        let error = eval_whnf_owned(&ir).expect_err("replaceStrings checks list lengths first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ReplaceStringsLengthMismatch {
                id: ir.root,
                from_len: 1,
                to_len: 0,
            }
        );
        assert_eq!(error.span(), root.span);
    }

    #[test]
    fn replace_strings_primop_forces_replacements_only_when_used() {
        assert_eq!(
            eval_string_bytes("builtins.replaceStrings [ \"x\" ] [ (1 / 0) ] \"z\""),
            b"z"
        );
        assert_eq!(
            eval_string_bytes("builtins.replaceStrings [ \"x\" ] [ 2 ] \"z\""),
            b"z"
        );
        assert_eq!(
            eval_string_bytes("builtins.replaceStrings [ \"z\" \"x\" ] [ \"y\" (1 / 0) ] \"z\""),
            b"y"
        );

        let ir = lower("builtins.replaceStrings [ \"x\" ] [ (1 / 0) ] \"x\"");
        let error = eval_whnf(&ir).expect_err("used replacement is forced");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. } | TreeWalkErrorKind::Force { .. }
        ));
    }

    #[test]
    fn replace_strings_primop_type_checks_arguments() {
        let ir = lower("builtins.replaceStrings 1 [] \"x\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let from = args[0];
        let from_span = ir.arena.node(from).expect("from argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("from must be a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: from,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), from_span);

        let ir = lower("builtins.replaceStrings [ 1 ] [ \"x\" ] \"1\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let from = args[0];
        let from_span = ir.arena.node(from).expect("from argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("from elements must be strings");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: from,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), from_span);

        let ir = lower("builtins.replaceStrings [ \"x\" ] [ 1 ] \"x\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let to = args[1];
        let to_span = ir.arena.node(to).expect("to argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("used replacements must be strings");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: to,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), to_span);

        let ir = lower("builtins.replaceStrings [ \"a\" ] [ \"x\" ] { outPath = \"a\"; }");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let string = args[2];
        let string_span = ir.arena.node(string).expect("string argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("string argument is not coerced");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: string,
                expected: "string",
                actual: ValueTag::Attrs,
            }
        );
        assert_eq!(error.span(), string_span);
    }

    #[test]
    fn replace_strings_primop_unions_source_and_used_replacement_contexts() {
        let ir = lower("builtins.replaceStrings [ \"x\" \"z\" ] [ \"used\" \"unused\" ] \"x\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let to = args[1];
        let to_span = ir.arena.node(to).expect("to argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);

        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let used = ContextElement::opaque_path(b"/nix/store/used".to_vec())
            .expect("used context is valid");
        let unused = ContextElement::opaque_path(b"/nix/store/unused".to_vec())
            .expect("unused context is valid");
        let used_value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"USED".to_vec(),
                StringContext::singleton(used.clone()).expect("used context allocates"),
            ))
            .expect("used replacement allocates");
        let unused_value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"UNUSED".to_vec(),
                StringContext::singleton(unused.clone()).expect("unused context allocates"),
            ))
            .expect("unused replacement allocates");
        let patterns = vec![
            ReplaceStringPattern {
                from: b"x".to_vec(),
                replacement: used_value,
            },
            ReplaceStringPattern {
                from: b"z".to_vec(),
                replacement: unused_value,
            },
        ];

        let result = evaluator
            .replace_strings_bytes(
                ir.root,
                root.span,
                to,
                to_span,
                b"prexpost",
                StringContext::singleton(source.clone()).expect("source context allocates"),
                &patterns,
            )
            .expect("replaceStrings evaluates");

        assert_eq!(result.bytes(), b"preUSEDpost");
        assert!(result.context().contains(&source));
        assert!(result.context().contains(&used));
        assert!(!result.context().contains(&unused));
    }

    #[test]
    fn concat_strings_sep_primop_joins_coerced_strings() {
        assert_eq!(eval_string_bytes("builtins.concatStringsSep \",\" []"), b"");
        assert_eq!(
            eval_string_bytes("builtins.concatStringsSep \",\" [ \"a\" ]"),
            b"a"
        );
        assert_eq!(
            eval_string_bytes("builtins.concatStringsSep \",\" [ \"a\" \"b\" \"c\" ]"),
            b"a,b,c"
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.concatStringsSep \",\" [ { outPath = \"a\"; } { __toString = self: \"b\"; } ]"
            ),
            b"a,b"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { concatStringsSep = sep: list: \"local\"; }; in builtins.concatStringsSep \",\" [ \"a\" \"b\" ]"
            ),
            b"local"
        );
    }

    #[test]
    fn concat_strings_sep_primop_checks_arguments_left_to_right() {
        let ir = lower("builtins.concatStringsSep 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let separator = args[0];
        let separator_span = ir
            .arena
            .node(separator)
            .expect("separator argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("separator is checked first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: separator,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), separator_span);

        let ir = lower("builtins.concatStringsSep { outPath = \",\"; } [ \"a\" ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let separator = args[0];
        let separator_span = ir
            .arena
            .node(separator)
            .expect("separator argument exists")
            .span;

        let error = eval_whnf_owned(&ir).expect_err("separator is not coerced");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: separator,
                expected: "string",
                actual: ValueTag::Attrs,
            }
        );
        assert_eq!(error.span(), separator_span);

        let ir = lower("builtins.concatStringsSep \",\" 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("second argument must be a list");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);

        let ir = lower("builtins.concatStringsSep \",\" [ \"a\" 1 ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("list elements must coerce to strings");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: list,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), list_span);
    }

    #[test]
    fn concat_strings_sep_primop_unions_separator_and_element_contexts() {
        let ir = lower("builtins.concatStringsSep \",\" []");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let list = args[1];
        let list_span = ir.arena.node(list).expect("list argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);

        let separator = ContextElement::opaque_path(b"/nix/store/separator".to_vec())
            .expect("separator context is valid");
        let element = ContextElement::opaque_path(b"/nix/store/element".to_vec())
            .expect("element context is valid");
        let element_value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"elem".to_vec(),
                StringContext::singleton(element.clone()).expect("element context allocates"),
            ))
            .expect("element string allocates");

        let empty = evaluator
            .concat_strings_sep_values(
                ir.root,
                root.span,
                list,
                list_span,
                b",",
                StringContext::singleton(separator.clone()).expect("separator context allocates"),
                &[],
            )
            .expect("empty concatStringsSep evaluates");

        assert_eq!(empty.bytes(), b"");
        assert!(empty.context().contains(&separator));

        let single = evaluator
            .concat_strings_sep_values(
                ir.root,
                root.span,
                list,
                list_span,
                b",",
                StringContext::singleton(separator.clone()).expect("separator context allocates"),
                &[element_value],
            )
            .expect("single-element concatStringsSep evaluates");

        assert_eq!(single.bytes(), b"elem");
        assert!(single.context().contains(&separator));
        assert!(single.context().contains(&element));
    }

    #[test]
    fn substring_primop_slices_coerced_string_bytes() {
        assert_eq!(eval_string_bytes("builtins.substring 1 2 \"abcd\""), b"bc");
        assert_eq!(eval_string_bytes("builtins.substring 10 2 \"abcd\""), b"");
        assert_eq!(
            eval_string_bytes("builtins.substring 1 999 \"abcd\""),
            b"bcd"
        );
        assert_eq!(
            eval_string_bytes("builtins.substring 1 (-1) \"abcd\""),
            b"bcd"
        );
        assert_eq!(
            eval_string_bytes("builtins.substring 2147483647 1 \"abcd\""),
            b""
        );
        assert_eq!(
            eval_string_bytes("builtins.substring 4294967296 1 \"abcd\""),
            b"a"
        );
        assert_eq!(
            eval_string_bytes("builtins.substring 4294967297 1 \"abcd\""),
            b"b"
        );
        assert_eq!(
            eval_string_bytes("builtins.substring (-9223372036854775807) 1 \"abcd\""),
            b"b"
        );
        assert_eq!(
            eval_string_bytes("builtins.substring 0 4294967296 \"abcd\""),
            b""
        );
        assert_eq!(
            eval_string_bytes("builtins.substring 0 4294967298 \"abcd\""),
            b"ab"
        );
        assert_eq!(
            eval_string_bytes("builtins.substring 0 (-4294967295) \"abcd\""),
            b"a"
        );
        assert_eq!(
            eval_string_bytes("builtins.substring 1 2 { outPath = \"abcd\"; }"),
            b"bc"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { substring = start: len: value: \"shadow\"; }; in builtins.substring 1 2 \"abcd\""
            ),
            b"shadow"
        );
    }

    #[test]
    fn substring_primop_checks_arguments_left_to_right() {
        let ir = lower("builtins.substring true (1 / 0) \"abcd\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let start = args[0];
        let start_span = ir.arena.node(start).expect("start exists").span;

        let error = eval_whnf(&ir).expect_err("substring type-checks start first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: start,
                expected: "int",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), start_span);

        let ir = lower("builtins.substring (-1) (1 / 0) \"abcd\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let start = args[0];
        let start_span = ir.arena.node(start).expect("start exists").span;

        let error = eval_whnf(&ir).expect_err("negative start rejects before length");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::NegativeSubstringStart {
                id: start,
                start: -1,
            }
        );
        assert_eq!(error.span(), start_span);

        let ir = lower("builtins.substring 2147483648 1 \"abcd\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let start = args[0];
        let start_span = ir.arena.node(start).expect("start exists").span;

        let error = eval_whnf(&ir).expect_err("oversized start matches Nix start rejection");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::NegativeSubstringStart {
                id: start,
                start: -2_147_483_648,
            }
        );
        assert_eq!(error.span(), start_span);

        let ir = lower("builtins.substring 4294967295 1 \"abcd\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let start = args[0];
        let start_span = ir.arena.node(start).expect("start exists").span;

        let error = eval_whnf(&ir).expect_err("wrapped negative start rejects");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::NegativeSubstringStart {
                id: start,
                start: -1,
            }
        );
        assert_eq!(error.span(), start_span);

        let ir = lower("builtins.substring 1 true (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let len = args[1];
        let len_span = ir.arena.node(len).expect("length exists").span;

        let error = eval_whnf(&ir).expect_err("substring type-checks length before string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: len,
                expected: "int",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), len_span);

        let ir = lower("builtins.substring 1 (-1) (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let string = args[2];
        let string_span = ir.arena.node(string).expect("string exists").span;

        let error = eval_whnf(&ir).expect_err("accepted negative length still forces string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: string }
        );
        assert_eq!(error.span(), string_span);
    }

    #[test]
    fn base_name_and_dir_of_primops_split_path_strings() {
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"/a/b\""), b"b");
        assert_eq!(eval_string_bytes("builtins.dirOf \"/a/b\""), b"/a");
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"\""), b"");
        assert_eq!(eval_string_bytes("builtins.dirOf \"\""), b".");
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"/\""), b"");
        assert_eq!(eval_string_bytes("builtins.dirOf \"/\""), b"/");
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"abc\""), b"abc");
        assert_eq!(eval_string_bytes("builtins.dirOf \"abc\""), b".");
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"a/b/c\""), b"c");
        assert_eq!(eval_string_bytes("builtins.dirOf \"a/b/c\""), b"a/b");
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"/a/b/\""), b"b");
        assert_eq!(eval_string_bytes("builtins.dirOf \"/a/b/\""), b"/a/b");
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"a//\""), b"");
        assert_eq!(eval_string_bytes("builtins.dirOf \"a//\""), b"a");
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"a//b\""), b"b");
        assert_eq!(eval_string_bytes("builtins.dirOf \"a//b\""), b"a");
        assert_eq!(eval_string_bytes("builtins.baseNameOf \"//a\""), b"a");
        assert_eq!(eval_string_bytes("builtins.dirOf \"//a\""), b"//");
    }

    #[test]
    fn base_name_and_dir_of_primops_coerce_and_shadow() {
        assert_eq!(
            eval_string_bytes("builtins.baseNameOf { outPath = \"/a/b\"; }"),
            b"b"
        );
        assert_eq!(
            eval_string_bytes("builtins.dirOf { __toString = self: \"/a/b\"; }"),
            b"/a"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { baseNameOf = value: \"shadow\"; }; in builtins.baseNameOf \"/a/b\""
            ),
            b"shadow"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { dirOf = value: \"shadow\"; }; in builtins.dirOf \"/a/b\""
            ),
            b"shadow"
        );
    }

    #[test]
    fn parse_drv_name_primop_splits_name_and_version() {
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo-1.2\").name"),
            b"foo"
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo-1.2\").version"),
            b"1.2"
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo-bar\").name"),
            b"foo-bar"
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo-bar\").version"),
            b""
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo--1\").name"),
            b"foo"
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo--1\").version"),
            b"-1"
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo-A-1\").name"),
            b"foo-A"
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo-A-1\").version"),
            b"1"
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo-é-1\").name"),
            b"foo"
        );
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"foo-é-1\").version"),
            "é-1".as_bytes()
        );
        assert_eq!(eval_string_bytes("(builtins.parseDrvName \"\").name"), b"");
        assert_eq!(
            eval_string_bytes("(builtins.parseDrvName \"-1\").version"),
            b"1"
        );
        assert_eq!(
            eval_list_string_bytes("builtins.attrNames (builtins.parseDrvName \"foo-1\")"),
            vec![b"name".to_vec(), b"version".to_vec()]
        );
        assert_eq!(
            eval("let builtins = { parseDrvName = x: { name = \"local\"; version = \"\"; }; }; in builtins.parseDrvName \"foo-1\" == { name = \"local\"; version = \"\"; }")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn parse_drv_name_primop_requires_a_string() {
        let ir = lower("builtins.parseDrvName 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("parseDrvName requires a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn split_version_primop_tokenizes_components() {
        assert_eq!(
            eval_list_string_bytes("builtins.splitVersion \"1.2.3\""),
            vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()]
        );
        assert_eq!(
            eval_list_string_bytes("builtins.splitVersion \"1.0pre2\""),
            vec![b"1".to_vec(), b"0".to_vec(), b"pre".to_vec(), b"2".to_vec()]
        );
        assert_eq!(
            eval_list_string_bytes("builtins.splitVersion \"foo-1.2_bar\""),
            vec![
                b"foo".to_vec(),
                b"1".to_vec(),
                b"2".to_vec(),
                b"_bar".to_vec()
            ]
        );
        assert_eq!(
            eval_list_string_bytes("builtins.splitVersion \"\""),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(
            eval_list_string_bytes("builtins.splitVersion \".1..2-\""),
            vec![b"1".to_vec(), b"2".to_vec()]
        );
        assert_eq!(
            eval_list_string_bytes("builtins.splitVersion \"1+2~pre\""),
            vec![
                b"1".to_vec(),
                b"+".to_vec(),
                b"2".to_vec(),
                b"~pre".to_vec()
            ]
        );
        assert_eq!(
            eval_list_string_bytes("builtins.splitVersion \"pre123post45\""),
            vec![
                b"pre".to_vec(),
                b"123".to_vec(),
                b"post".to_vec(),
                b"45".to_vec()
            ]
        );
        assert_eq!(
            eval_list_string_bytes("builtins.splitVersion \"é1β2\""),
            vec![
                "é".as_bytes().to_vec(),
                b"1".to_vec(),
                "β".as_bytes().to_vec(),
                b"2".to_vec()
            ]
        );
        assert_eq!(
            eval("let builtins = { splitVersion = x: [ \"local\" ]; }; in builtins.splitVersion \"1.0\" == [ \"local\" ]")
                .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn split_version_primop_requires_a_string() {
        let ir = lower("builtins.splitVersion 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("splitVersion requires a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn split_version_primop_rejects_string_context() {
        let ir = lower("builtins.splitVersion \"1.0\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("splitVersion argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"1.0".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing string allocates");

        let error = evaluator
            .eval_split_version_primop(ir.root, root.span, argument, argument_span, value)
            .expect_err("splitVersion rejects string context");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextNotAllowed {
                id: argument,
                op: "splitVersion",
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn hash_string_primop_hashes_bytes() {
        assert_eq!(
            eval_string_bytes("builtins.hashString \"md5\" \"abc\""),
            b"900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            eval_string_bytes("builtins.hashString \"sha1\" \"abc\""),
            b"a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            eval_string_bytes("builtins.hashString \"sha256\" \"abc\""),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            eval_string_bytes("builtins.hashString \"sha512\" \"abc\""),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { hashString = type: value: \"local\"; }; in builtins.hashString \"sha256\" \"abc\""
            ),
            b"local"
        );
    }

    #[test]
    fn first_class_binary_builtin_selects_are_curried() {
        assert_eq!(
            eval_string_bytes("let h = builtins.hashString \"sha256\"; in h \"abc\""),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(eval("let add = builtins.add 1; in add 2").as_int(), Ok(3));
        assert_eq!(
            eval("let less = builtins.lessThan 1; in less 2").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let cmp = builtins.compareVersions \"1.2\"; in cmp \"1.10\"").as_int(),
            Ok(-1)
        );
        assert_eq!(
            eval_string_bytes("let get = builtins.getAttr \"a\"; in get { a = \"x\"; }"),
            b"x"
        );
        assert_eq!(
            eval("let has = builtins.hasAttr \"a\"; in has { a = 1; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let remove = builtins.removeAttrs { a = 1; b = 2; }; in remove [ \"a\" ] == { b = 2; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let intersect = builtins.intersectAttrs { a = 0; c = 0; }; in intersect { a = 1; b = 2; } == { a = 1; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval_list_ints(
                "let cat = builtins.catAttrs \"a\"; in cat [ { a = 1; } { b = 2; } { a = 3; } ]"
            ),
            vec![1, 3]
        );
        assert_eq!(
            eval_string_bytes(
                "let join = builtins.concatStringsSep \",\"; in join [ \"a\" \"b\" ]"
            ),
            b"a,b"
        );
        assert_eq!(
            eval("let s = builtins.seq (1 / 0); in builtins.isFunction s").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let s = builtins.seq 1; in builtins.length (s [ 1 (1 / 0) ])").as_int(),
            Ok(2)
        );
    }

    #[test]
    fn first_class_binary_builtin_type_checks_left_before_right() {
        for (source, expected, actual) in [
            (
                "let cmp = builtins.compareVersions 1; in cmp (1 / 0)",
                "string",
                ValueTag::Int,
            ),
            (
                "let and = builtins.bitAnd true; in and (1 / 0)",
                "int",
                ValueTag::Bool,
            ),
        ] {
            let error = eval_whnf_owned(&lower(source)).expect_err("left argument is rejected");

            let TreeWalkErrorKind::Type {
                expected: found_expected,
                actual: found_actual,
                ..
            } = error.kind()
            else {
                panic!("expected a type error for {source}, got {error:?}");
            };
            assert_eq!(found_expected, expected, "{source}");
            assert_eq!(found_actual, actual, "{source}");
        }
    }

    #[test]
    fn first_class_ternary_builtin_selects_are_curried() {
        assert_eq!(
            eval("let fold = builtins.foldl' builtins.add; sum = fold 0; in sum [ 1 2 3 ]")
                .as_int(),
            Ok(6)
        );
        assert_eq!(
            eval_string_bytes(
                "let slice = builtins.substring 1; take2 = slice 2; in take2 \"abcd\""
            ),
            b"bc"
        );
        assert_eq!(
            eval_string_bytes(
                "let replace = builtins.replaceStrings [ \"a\" ]; swap = replace [ \"b\" ]; in swap \"a\""
            ),
            b"b"
        );
    }

    #[test]
    fn hash_string_primop_hashes_context_bearing_string_bytes() {
        let ir = lower("builtins.hashString \"sha256\" \"abc\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let algorithm = args[0];
        let string = args[1];
        let string_span = ir.arena.node(string).expect("string argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"abc".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing string allocates");

        let result = evaluator
            .eval_hash_string_primop_with_string_value(
                ir.root,
                root.span,
                algorithm,
                string,
                string_span,
                value,
            )
            .expect("hashString evaluates");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result is a string");

        assert_eq!(
            string.bytes(),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!string.has_context());
    }

    #[test]
    fn hash_string_primop_rejects_context_bearing_algorithm() {
        let ir = lower("builtins.hashString \"sha256\" (1 / 0)");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let algorithm = args[0];
        let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"sha256".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing algorithm allocates");

        let error = evaluator
            .eval_hash_algorithm(algorithm, algorithm_span, value, "hashString")
            .expect_err("hashString rejects algorithm string context");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextNotAllowed {
                id: algorithm,
                op: "hashString",
            }
        );
        assert_eq!(error.span(), algorithm_span);
    }

    #[test]
    fn hash_string_primop_checks_algorithm_before_string() {
        let ir = lower("builtins.hashString \"bad\" (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let algorithm = args[0];
        let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

        let error = eval_whnf_owned(&ir).expect_err("unknown algorithm is rejected first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnknownHashAlgorithm {
                id: algorithm,
                algorithm: b"bad".to_vec(),
            }
        );
        assert_eq!(error.span(), algorithm_span);

        let ir = lower("builtins.hashString \"SHA256\" \"abc\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let algorithm = args[0];

        let error = eval_whnf_owned(&ir).expect_err("algorithm names are case-sensitive");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnknownHashAlgorithm {
                id: algorithm,
                algorithm: b"SHA256".to_vec(),
            }
        );
    }

    #[test]
    fn hash_string_primop_type_checks_arguments() {
        let ir = lower("builtins.hashString 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let algorithm = args[0];
        let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

        let error = eval_whnf_owned(&ir).expect_err("algorithm must be a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: algorithm,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), algorithm_span);

        let ir = lower("builtins.hashString \"sha256\" { outPath = \"abc\"; }");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let string = args[1];
        let string_span = ir.arena.node(string).expect("string exists").span;

        let error = eval_whnf_owned(&ir).expect_err("string argument is not coerced");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: string,
                expected: "string",
                actual: ValueTag::Attrs,
            }
        );
        assert_eq!(error.span(), string_span);
    }

    #[test]
    fn convert_hash_primop_converts_formats() {
        let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base64\"; }}"
            )),
            b"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"nix32\"; }}"
            )),
            b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base32\"; }}"
            )),
            b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"sri\"; }}"
            )),
            b"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
            ),
            sha256.as_bytes()
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = \"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
            ),
            sha256.as_bytes()
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; toHashFormat = \"base16\"; }"
            ),
            sha256.as_bytes()
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0\"; toHashFormat = \"base16\"; }"
            ),
            sha256.as_bytes()
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = \"sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s\"; toHashFormat = \"base16\"; }"
            ),
            sha256.as_bytes()
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.convertHash {{ hash = \"sha256:{sha256}\"; toHashFormat = \"base16\"; }}"
            )),
            sha256.as_bytes()
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = builtins.hashString \"md5\" \"abc\"; hashAlgo = \"md5\"; toHashFormat = \"nix32\"; }"
            ),
            b"3jgzhjhz9zjvbb0kyj7jc500ch"
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = builtins.hashString \"sha1\" \"abc\"; hashAlgo = \"sha1\"; toHashFormat = \"base64\"; }"
            ),
            b"qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = builtins.hashString \"sha512\" \"abc\"; hashAlgo = \"sha512\"; toHashFormat = \"nix32\"; }"
            ),
            b"2gs8k559z4rlahfx0y688s49m2vvszylcikrfinm30ly9rak69236nkam5ydvly1ai7xac99vxfc4ii84hawjbk876blyk1jfhkbbyx"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { convertHash = args: \"local\"; }; in builtins.convertHash { hash = 1 / 0; }"
            ),
            b"local"
        );
    }

    #[test]
    fn convert_hash_primop_can_be_selected_as_a_function() {
        assert_eq!(
            eval_string_bytes(
                "let convert = builtins.convertHash; in convert { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
            ),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn convert_hash_primop_checks_arguments_in_nix_order() {
        let ir = lower("builtins.convertHash 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("convertHash argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("argument must be an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = 1 / 0; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
        ))
        .expect_err("hash is forced first");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
        ))
        .expect_err("hashAlgo is forced second");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = 1 / 0; }",
        ))
        .expect_err("toHashFormat is forced third");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn convert_hash_primop_reports_missing_attributes() {
        let ir =
            lower("builtins.convertHash { hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("convertHash argument exists");
        let mut evaluator = TreeWalk::new(&ir);

        let error = evaluator
            .eval_root()
            .expect_err("convertHash requires hash");

        let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
            panic!("expected missing hash attribute");
        };
        assert_eq!(id, argument);
        assert_eq!(evaluator.symbols.resolve(symbol), Some(b"hash".as_slice()));

        let ir = lower(
            "builtins.convertHash { hash = builtins.hashString \"sha256\" \"abc\"; hashAlgo = \"sha256\"; }",
        );
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("convertHash argument exists");
        let mut evaluator = TreeWalk::new(&ir);

        let error = evaluator
            .eval_root()
            .expect_err("convertHash requires toHashFormat");

        let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
            panic!("expected missing toHashFormat attribute");
        };
        assert_eq!(id, argument);
        assert_eq!(
            evaluator.symbols.resolve(symbol),
            Some(b"toHashFormat".as_slice())
        );
    }

    #[test]
    fn convert_hash_primop_requires_direct_strings() {
        let ir = lower(
            "builtins.convertHash { hash = { outPath = \"abc\"; }; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        );
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("convertHash argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("hash is not coerced");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Attrs,
            }
        );
        assert_eq!(error.span(), argument_span);

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = null; toHashFormat = \"base16\"; }",
        ))
        .expect_err("hashAlgo must be a string when present");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "string",
                actual: ValueTag::Null,
                ..
            }
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = { outPath = \"base16\"; }; }",
        ))
        .expect_err("toHashFormat is not coerced");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Type {
                expected: "string",
                actual: ValueTag::Attrs,
                ..
            }
        ));
    }

    #[test]
    fn convert_hash_primop_rejects_invalid_hashes() {
        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"bad\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("unknown algorithm is rejected");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::UnknownHashAlgorithm { algorithm, .. }
                if algorithm.as_slice() == b"bad"
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"bad\"; }",
        ))
        .expect_err("unknown format is rejected");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::UnknownHashFormat { format, .. }
                if format.as_slice() == b"bad"
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("untyped hashes require hashAlgo");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::HashAlgorithmRequired { hash, .. }
                if hash.as_slice() == b"abc"
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"md5\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("typed hashes must agree with hashAlgo");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::HashAlgorithmMismatch { expected, .. }
                if expected.as_slice() == b"md5"
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("short hashes are rejected");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::HashWrongLength { hash, algorithm, .. }
                if hash.as_slice() == b"abc" && algorithm.as_slice() == b"sha256"
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid hex hashes are rejected");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::InvalidBase16Hash { .. }
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"????????????????????????????????????????????\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid base64 hashes are rejected");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::InvalidBase64Hash { .. }
        ));

        let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256-invalid\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid SRI hashes are rejected");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::InvalidSriHash { .. }
        ));
    }

    #[test]
    fn path_literals_evaluate_as_paths_without_store_coercion() {
        let (dir, path) = temp_file_with_bytes("path-literal", b"abc");
        let path = path_source(&path);

        assert_eq!(
            eval_string_bytes(&format!("builtins.typeOf {path}")),
            b"path"
        );
        assert_eq!(eval(&format!("builtins.isPath {path}")).as_bool(), Ok(true));
        assert_eq!(eval(&format!("{path} == {path}")).as_bool(), Ok(true));

        let ir = lower(&format!("builtins.toJSON {path}"));
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let path_id = args[0];
        let path_span = ir.arena.node(path_id).expect("path exists").span;
        let error = eval_whnf_owned(&ir).expect_err("store-path JSON coercion is unsupported");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::JsonUnsupportedValue {
                id: path_id,
                actual: ValueTag::Path,
            }
        );
        assert_eq!(error.span(), path_span);

        let ir = lower("./relative-file");
        let path_span = ir.arena.node(ir.root).expect("path exists").span;
        let error = eval_whnf_owned(&ir).expect_err("relative path literals need a source base");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::PathNotAbsolute {
                id: ir.root,
                path: b"./relative-file".to_vec(),
            }
        );
        assert_eq!(error.span(), path_span);

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn hash_file_primop_hashes_file_contents() {
        let (dir, path) = temp_file_with_bytes("hash-file", b"abc");
        let path = path_source(&path);

        assert_eq!(
            eval_string_bytes(&format!("builtins.hashFile \"md5\" {path}")),
            b"900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            eval_string_bytes(&format!("builtins.hashFile \"sha1\" {path}")),
            b"a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            eval_string_bytes(&format!("builtins.hashFile \"sha256\" {path}")),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            eval_string_bytes(&format!("builtins.hashFile \"sha512\" {path}")),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.hashFile \"sha256\" {}",
                nix_string_literal(&path)
            )),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.hashFile \"sha256\" {{ outPath = {}; }}",
                nix_string_literal(&path)
            )),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { hashFile = type: path: \"local\"; }; in builtins.hashFile \"sha256\" \"relative.txt\""
            ),
            b"local"
        );

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn hash_file_primop_rejects_context_bearing_algorithm() {
        let ir = lower("builtins.hashFile \"sha256\" ./crates/Cargo.toml");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let algorithm = args[0];
        let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"sha256".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing algorithm allocates");

        let error = evaluator
            .eval_hash_algorithm(algorithm, algorithm_span, value, "hashFile")
            .expect_err("hashFile rejects algorithm string context");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextNotAllowed {
                id: algorithm,
                op: "hashFile",
            }
        );
        assert_eq!(error.span(), algorithm_span);
    }

    #[test]
    fn hash_file_primop_checks_algorithm_before_path() {
        let ir = lower("builtins.hashFile \"bad\" (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let algorithm = args[0];
        let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

        let error = eval_whnf_owned(&ir).expect_err("unknown algorithm is rejected first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnknownHashAlgorithm {
                id: algorithm,
                algorithm: b"bad".to_vec(),
            }
        );
        assert_eq!(error.span(), algorithm_span);

        let error = eval_whnf_owned(&lower("builtins.hashFile \"sha256\" (1 / 0)"))
            .expect_err("valid algorithm demands path argument");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn hash_file_primop_rejects_relative_strings() {
        let ir = lower("builtins.hashFile \"sha256\" \"relative.txt\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let path = args[1];
        let path_span = ir.arena.node(path).expect("path exists").span;

        let error = eval_whnf_owned(&ir).expect_err("relative strings are rejected");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::PathNotAbsolute {
                id: path,
                path: b"relative.txt".to_vec(),
            }
        );
        assert_eq!(error.span(), path_span);
    }

    #[test]
    fn hash_file_primop_reports_file_read_errors() {
        let dir = unique_temp_dir("hash-file-missing");
        let path = path_source(&dir.join("missing.txt"));
        let ir = lower(&format!(
            "builtins.hashFile \"sha256\" {}",
            nix_string_literal(&path)
        ));
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let path_id = args[1];
        let path_span = ir.arena.node(path_id).expect("path exists").span;

        let error = eval_whnf_owned(&ir).expect_err("missing file is reported");

        match error.kind() {
            TreeWalkErrorKind::FileRead {
                id,
                path: actual,
                message,
            } => {
                assert_eq!(id, path_id);
                assert_eq!(actual.as_slice(), path.as_bytes());
                assert!(!message.is_empty());
            }
            other => panic!("expected file-read error, got {other:?}"),
        }
        assert_eq!(error.span(), path_span);

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn path_exists_primop_checks_filesystem_presence() {
        let dir = unique_temp_dir("path-exists");
        let file = dir.join("regular.txt");
        let dangling = dir.join("dangling");
        fs::write(&file, b"data").expect("regular file writes");
        std::os::unix::fs::symlink(dir.join("missing-target"), &dangling)
            .expect("dangling symlink creates");
        let dir_path = path_source(&dir);
        let file_path = path_source(&file);
        let dangling_path = path_source(&dangling);
        let missing_path = path_source(&dir.join("missing.txt"));

        assert_eq!(
            eval(&format!(
                "builtins.pathExists {}",
                nix_string_literal(&file_path)
            ))
            .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(&format!(
                "builtins.pathExists {}",
                nix_string_literal(&missing_path)
            ))
            .as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval(&format!(
                "builtins.pathExists {}",
                nix_string_literal(&dangling_path)
            ))
            .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(&format!(
                "builtins.pathExists {}",
                nix_string_literal(&format!("{dangling_path}/"))
            ))
            .as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval(&format!(
                "builtins.pathExists {}",
                nix_string_literal(&format!("{dir_path}/"))
            ))
            .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(&format!(
                "builtins.pathExists {}",
                nix_string_literal(&format!("{file_path}/"))
            ))
            .as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval(&format!(
                "builtins.pathExists {}",
                nix_string_literal(&format!("{file_path}/."))
            ))
            .as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval(&format!(
                "builtins.pathExists {{ outPath = {}; }}",
                nix_string_literal(&format!("{file_path}/"))
            ))
            .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(&format!(
                "builtins.pathExists {{ outPath = {}; }}",
                nix_string_literal(&format!("{file_path}/."))
            ))
            .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(&format!(
                "let f = builtins.pathExists; in f {}",
                nix_string_literal(&file_path)
            ))
            .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let builtins = { pathExists = path: false; }; in builtins.pathExists \"/\"")
                .as_bool(),
            Ok(false)
        );

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn path_exists_primop_type_checks_and_rejects_relative_strings() {
        let ir = lower("builtins.pathExists 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("pathExists requires a path");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.pathExists \"relative.txt\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("relative strings are rejected");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::PathNotAbsolute {
                id: argument,
                path: b"relative.txt".to_vec(),
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn read_file_type_primop_reports_filesystem_node_types() {
        let dir = unique_temp_dir("read-file-type");
        let regular = dir.join("regular");
        let nested = dir.join("nested");
        let link = dir.join("link");
        let link_dir = dir.join("link-dir");
        let dangling = dir.join("dangling");
        fs::write(&regular, b"data").expect("regular file writes");
        fs::create_dir(&nested).expect("nested directory creates");
        std::os::unix::fs::symlink(&regular, &link).expect("symlink creates");
        std::os::unix::fs::symlink(&nested, &link_dir).expect("directory symlink creates");
        std::os::unix::fs::symlink(dir.join("missing-target"), &dangling)
            .expect("dangling symlink creates");
        let regular_path = path_source(&regular);
        let nested_path = path_source(&nested);
        let link_path = path_source(&link);
        let link_dir_path = path_source(&link_dir);
        let dangling_path = path_source(&dangling);

        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&regular_path)
            )),
            b"regular"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&nested_path)
            )),
            b"directory"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&link_path)
            )),
            b"symlink"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&format!("{regular_path}/"))
            )),
            b"regular"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&format!("{regular_path}/."))
            )),
            b"regular"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&format!("{link_dir_path}/"))
            )),
            b"symlink"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&format!("{link_dir_path}/."))
            )),
            b"symlink"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&format!("{dangling_path}/"))
            )),
            b"symlink"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFileType {}",
                nix_string_literal(&format!("{dangling_path}/."))
            )),
            b"symlink"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "let f = builtins.readFileType; in f {}",
                nix_string_literal(&regular_path)
            )),
            b"regular"
        );

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn read_file_type_primop_reports_stat_errors() {
        let dir = unique_temp_dir("read-file-type-missing");
        let missing_path = path_source(&dir.join("missing"));
        let ir = lower(&format!(
            "builtins.readFileType {}",
            nix_string_literal(&missing_path)
        ));
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("missing path is reported");

        match error.kind() {
            TreeWalkErrorKind::PathStat { id, path, message } => {
                assert_eq!(id, argument);
                assert_eq!(path.as_slice(), missing_path.as_bytes());
                assert!(!message.is_empty());
            }
            other => panic!("expected stat error, got {other:?}"),
        }
        assert_eq!(error.span(), argument_span);

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn read_dir_primop_lists_entry_types() {
        let dir = unique_temp_dir("read-dir");
        let regular = dir.join("regular");
        let nested = dir.join("nested");
        let link = dir.join("link");
        fs::write(&regular, b"data").expect("regular file writes");
        fs::create_dir(&nested).expect("nested directory creates");
        std::os::unix::fs::symlink(&regular, &link).expect("symlink creates");
        let dir_path = path_source(&dir);

        assert_eq!(
            eval_list_string_bytes(&format!(
                "builtins.attrNames (builtins.readDir {})",
                nix_string_literal(&dir_path)
            )),
            vec![b"link".to_vec(), b"nested".to_vec(), b"regular".to_vec()]
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "(builtins.readDir {}).link",
                nix_string_literal(&dir_path)
            )),
            b"symlink"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "(builtins.readDir {}).nested",
                nix_string_literal(&dir_path)
            )),
            b"directory"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "(builtins.readDir {}).regular",
                nix_string_literal(&dir_path)
            )),
            b"regular"
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "let f = builtins.readDir; d = f {}; in d.regular",
                nix_string_literal(&dir_path)
            )),
            b"regular"
        );

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn read_dir_primop_type_checks_and_reports_directory_errors() {
        let ir = lower("builtins.readDir 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("readDir requires a path");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);

        let dir = unique_temp_dir("read-dir-file");
        let regular = dir.join("regular");
        fs::write(&regular, b"data").expect("regular file writes");
        let regular_path = path_source(&regular);
        let ir = lower(&format!(
            "builtins.readDir {}",
            nix_string_literal(&regular_path)
        ));
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("file is not a directory");

        match error.kind() {
            TreeWalkErrorKind::DirectoryRead { id, path, message } => {
                assert_eq!(id, argument);
                assert_eq!(path.as_slice(), regular_path.as_bytes());
                assert!(!message.is_empty());
            }
            other => panic!("expected directory-read error, got {other:?}"),
        }
        assert_eq!(error.span(), argument_span);

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn to_string_primop_converts_scalar_values() {
        assert_eq!(eval_string_bytes("builtins.toString \"x\""), b"x");
        assert_eq!(eval_string_bytes("builtins.toString 1"), b"1");
        assert_eq!(eval_string_bytes("builtins.toString (-2)"), b"-2");
        assert_eq!(eval_string_bytes("builtins.toString 1.25"), b"1.250000");
        assert_eq!(eval_string_bytes("builtins.toString (-0.0)"), b"0.000000");
        assert_eq!(
            eval_string_bytes("builtins.toString ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))"),
            b"nan"
        );
        assert_eq!(eval_string_bytes("builtins.toString true"), b"1");
        assert_eq!(eval_string_bytes("builtins.toString false"), b"");
        assert_eq!(eval_string_bytes("builtins.toString null"), b"");
        assert_eq!(
            eval_string_bytes(
                "let builtins = { toString = x: \"local\"; }; in builtins.toString 1"
            ),
            b"local"
        );
    }

    #[test]
    fn to_string_primop_flattens_lists_with_spaces() {
        assert_eq!(
            eval_string_bytes("builtins.toString [ 1 \"x\" true false null ]"),
            b"1 x 1  "
        );
        assert_eq!(
            eval_string_bytes("builtins.toString [ \"x\" [] \"y\" ]"),
            b"x y"
        );
        assert_eq!(
            eval_string_bytes("builtins.toString [ \"x\" [ \"\" ] \"y\" ]"),
            b"x  y"
        );
        assert_eq!(
            eval_string_bytes(
                "builtins.toString [ [ \"a\" \"b\" ] [ \"c\" \"\" ] [ \"\" \"d\" ] ]"
            ),
            b"a b c   d"
        );
        assert_eq!(eval_string_bytes("builtins.toString [ \"\" \"\" ]"), b" ");
    }

    #[test]
    fn to_string_primop_coerces_attrsets_with_full_to_string_rules() {
        assert_eq!(
            eval_string_bytes("builtins.toString { __toString = self: 1; outPath = 1 / 0; }"),
            b"1"
        );
        assert_eq!(
            eval_string_bytes("builtins.toString { __toString = self: [ \"a\" \"b\" ]; }"),
            b"a b"
        );
        assert_eq!(
            eval_string_bytes("builtins.toString { outPath = [ \"a\" \"b\" ]; }"),
            b"a b"
        );
        assert_eq!(
            eval_string_bytes("builtins.toString [ \"x\" { __toString = self: []; } \"y\" ]"),
            b"x  y"
        );
    }

    #[test]
    fn to_string_primop_forces_arguments_and_rejects_non_coercible_values() {
        let ir = lower("builtins.toString [ \"a\" (1 / 0) ]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let _argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("toString argument exists");

        let error = eval_whnf_owned(&ir).expect_err("toString forces list elements");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let ir = lower("builtins.toString (x: x)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("toString argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("functions are not string-coercible");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Lambda,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn to_string_primop_preserves_string_contexts() {
        let ir = lower("builtins.toString []");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("toString argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let first_context = ContextElement::opaque_path(b"/nix/store/first".to_vec())
            .expect("first context builds");
        let second_context = ContextElement::opaque_path(b"/nix/store/second".to_vec())
            .expect("second context builds");
        let first = evaluator
            .heap
            .alloc_string(NixString::new(
                b"a".to_vec(),
                StringContext::singleton(first_context.clone()).expect("first context allocates"),
            ))
            .expect("first string allocates");
        let second = evaluator
            .heap
            .alloc_string(NixString::new(
                b"b".to_vec(),
                StringContext::singleton(second_context.clone()).expect("second context allocates"),
            ))
            .expect("second string allocates");
        let list = evaluator
            .heap
            .alloc_list(NixList::new(vec![first, Value::int(1), second]))
            .expect("list allocates");

        let result = evaluator
            .eval_to_string_primop(ir.root, root.span, argument, argument_span, list)
            .expect("toString evaluates");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result is a string");

        assert_eq!(string.bytes(), b"a 1 b");
        assert!(string.context().contains(&first_context));
        assert!(string.context().contains(&second_context));
    }

    #[test]
    fn to_json_primop_serializes_scalars_and_containers() {
        assert_eq!(eval_string_bytes("builtins.toJSON null"), b"null");
        assert_eq!(eval_string_bytes("builtins.toJSON true"), b"true");
        assert_eq!(eval_string_bytes("builtins.toJSON false"), b"false");
        assert_eq!(eval_string_bytes("builtins.toJSON 42"), b"42");
        assert_eq!(
            eval_string_bytes("builtins.toJSON \"é\""),
            "\"é\"".as_bytes()
        );
        assert_eq!(
            eval_string_bytes("builtins.toJSON \"\\t\\r\\n\\\\\\\"\""),
            br#""\t\r\n\\\"""#
        );
        assert_eq!(
            eval_string_bytes(r#"builtins.toJSON (builtins.fromJSON "\"\\b\"")"#),
            br#""\b""#
        );
        assert_eq!(
            eval_string_bytes(r#"builtins.toJSON (builtins.fromJSON "\"\\f\"")"#),
            br#""\f""#
        );
        assert_eq!(
            eval_string_bytes("builtins.toJSON { b = 1; a = [ true false null \"x\" ]; }"),
            br#"{"a":[true,false,null,"x"],"b":1}"#
        );
        assert_eq!(
            eval_string_bytes("builtins.toJSON { \"10\" = 10; \"2\" = 2; A = 1; a = 2; }"),
            br#"{"10":10,"2":2,"A":1,"a":2}"#
        );
    }

    #[test]
    fn to_json_primop_formats_floats_like_cpp_nix_json() {
        assert_eq!(eval_string_bytes("builtins.toJSON 1.0"), b"1.0");
        assert_eq!(eval_string_bytes("builtins.toJSON 1.50"), b"1.5");
        assert_eq!(eval_string_bytes("builtins.toJSON (-0.0)"), b"0.0");
        assert_eq!(eval_string_bytes("builtins.toJSON 0.000001"), b"1e-06");
        assert_eq!(
            eval_string_bytes("builtins.toJSON 100000000000000000000.0"),
            b"1e+20"
        );
        assert_eq!(
            eval_string_bytes("builtins.toJSON ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))"),
            b"null"
        );
        assert_eq!(
            eval_string_bytes("builtins.toJSON (1.0e308 * 1.0e308)"),
            b"null"
        );
    }

    #[test]
    fn to_json_primop_coerces_special_attrsets() {
        assert_eq!(
            eval_string_bytes(
                "builtins.toJSON { __toString = self: \"hook\"; outPath = \"out\"; }"
            ),
            br#""hook""#
        );
        assert_eq!(
            eval_string_bytes("builtins.toJSON { __toString = self: { outPath = \"nested\"; }; }"),
            br#""nested""#
        );
        assert_eq!(
            eval_string_bytes("builtins.toJSON { outPath = [ \"a\" \"b\" ]; }"),
            br#"["a","b"]"#
        );
        assert_eq!(
            eval_string_bytes("builtins.toJSON { outPath = \"out\"; a = 1; }"),
            br#""out""#
        );
        assert_eq!(eval_string_bytes("builtins.toJSON {}"), b"{}");
    }

    #[test]
    fn to_json_primop_reports_attr_coercion_and_unsupported_values() {
        let ir = lower("builtins.toJSON { __toString = self: 1; }");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("toJSON argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("__toString result must be a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.toJSON [ (x: x) ]");
        let error = eval_whnf_owned(&ir).expect_err("functions cannot become JSON");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::JsonUnsupportedValue {
                actual: ValueTag::Lambda,
                ..
            }
        ));

        let ir = lower("builtins.toJSON [ 1 (1 / 0) ]");
        let error = eval_whnf_owned(&ir).expect_err("toJSON forces list elements");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn to_json_primop_unions_string_contexts() {
        let ir = lower("builtins.toJSON []");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("toJSON argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let direct_context = ContextElement::opaque_path(b"/nix/store/direct".to_vec())
            .expect("direct context builds");
        let out_path_context = ContextElement::opaque_path(b"/nix/store/out-path".to_vec())
            .expect("outPath context builds");
        let direct = evaluator
            .heap
            .alloc_string(NixString::new(
                b"direct".to_vec(),
                StringContext::singleton(direct_context.clone()).expect("direct context allocates"),
            ))
            .expect("direct string allocates");
        let out_path = evaluator
            .heap
            .alloc_string(NixString::new(
                b"out".to_vec(),
                StringContext::singleton(out_path_context.clone())
                    .expect("outPath context allocates"),
            ))
            .expect("outPath string allocates");
        let out_path_symbol = evaluator
            .symbols
            .intern(OUT_PATH_ATTR)
            .expect("outPath symbol interns");
        let attrs = FlatAttrs::new(
            vec![AttrEntry::new(out_path_symbol, out_path)],
            &evaluator.symbols,
        )
        .expect("attrs build");
        let attrs = evaluator
            .heap
            .alloc_attrs(0, attrs)
            .expect("attrs allocate");
        let list = evaluator
            .heap
            .alloc_list(NixList::new(vec![direct, attrs]))
            .expect("list allocates");

        let result = evaluator
            .eval_to_json_primop(ir.root, root.span, argument, argument_span, list)
            .expect("toJSON evaluates");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result is a string");

        assert_eq!(string.bytes(), br#"["direct","out"]"#);
        assert!(string.context().contains(&direct_context));
        assert!(string.context().contains(&out_path_context));
    }

    #[test]
    fn from_json_primop_decodes_json_values() {
        let json = r#"''{"b":1,"a":[true,false,null,"x"],"c":{"n":2.5}}''"#;
        assert_eq!(
            eval_list_string_bytes(&format!("builtins.attrNames (builtins.fromJSON {json})")),
            [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
        assert_eq!(
            eval(&format!("builtins.elemAt (builtins.fromJSON {json}).a 0")).as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(&format!("builtins.elemAt (builtins.fromJSON {json}).a 1")).as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval(&format!("builtins.elemAt (builtins.fromJSON {json}).a 2")).as_null(),
            Ok(())
        );
        assert_eq!(
            eval_string_bytes(&format!("builtins.elemAt (builtins.fromJSON {json}).a 3")),
            b"x"
        );
        assert_eq!(
            eval(&format!("(builtins.fromJSON {json}).b")).as_int(),
            Ok(1)
        );
        assert_eq!(
            eval(&format!("(builtins.fromJSON {json}).c.n")).as_float(),
            Ok(2.5)
        );
        assert_eq!(
            eval_string_bytes(r#"builtins.fromJSON ''"é"''"#),
            "é".as_bytes()
        );
        assert_eq!(
            eval(r#"let builtins = { fromJSON = x: 42; }; in builtins.fromJSON "{}""#).as_int(),
            Ok(42)
        );
    }

    #[test]
    fn from_json_primop_matches_number_edges_and_duplicate_keys() {
        assert_eq!(
            eval(r#"builtins.fromJSON "9223372036854775808""#).as_int(),
            Ok(i64::MIN)
        );
        assert_eq!(
            eval(r#"builtins.fromJSON "18446744073709551615""#).as_int(),
            Ok(-1)
        );
        assert_eq!(
            eval_string_bytes(r#"builtins.typeOf (builtins.fromJSON "-9223372036854775809")"#),
            b"float"
        );
        assert_eq!(
            eval(r#"(builtins.fromJSON ''{"a":1,"a":2}'').a"#).as_int(),
            Ok(2)
        );
    }

    #[test]
    fn from_json_primop_checks_argument_and_json() {
        let ir = lower("builtins.fromJSON 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("fromJSON requires a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower(r#"builtins.fromJSON "01""#);
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("fromJSON rejects invalid JSON");

        match error.kind() {
            TreeWalkErrorKind::JsonParse { id, message } => {
                assert_eq!(id, argument);
                assert!(!message.is_empty());
            }
            kind => panic!("unexpected error kind: {kind:?}"),
        }
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn from_json_primop_rejects_string_context() {
        let ir = lower("builtins.fromJSON \"{}\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("fromJSON argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"{}".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing string allocates");

        let error = evaluator
            .eval_from_json_primop(argument, argument_span, value)
            .expect_err("fromJSON rejects string context");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextNotAllowed {
                id: argument,
                op: "fromJSON",
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn compare_versions_primop_orders_components() {
        for (source, expected) in [
            ("builtins.compareVersions \"1.0\" \"1.0\"", 0),
            ("builtins.compareVersions \"1.0\" \"1.1\"", -1),
            ("builtins.compareVersions \"1.10\" \"1.2\"", 1),
            ("builtins.compareVersions \"1.0pre\" \"1.0\"", -1),
            ("builtins.compareVersions \"1.0\" \"1.0pre\"", 1),
            ("builtins.compareVersions \"1.0pre2\" \"1.0pre10\"", -1),
            ("builtins.compareVersions \"1.0\" \"1.0.0\"", -1),
            ("builtins.compareVersions \"01\" \"1\"", 0),
            ("builtins.compareVersions \"1a\" \"1.0\"", -1),
            ("builtins.compareVersions \"1.0+git\" \"1.0\"", 1),
        ] {
            assert_eq!(eval(source).as_int(), Ok(expected), "{source}");
        }
        assert_eq!(
            eval("let builtins = { compareVersions = left: right: 42; }; in builtins.compareVersions \"1.0\" \"1.1\"")
                .as_int(),
            Ok(42)
        );
    }

    #[test]
    fn compare_versions_primop_checks_arguments_left_to_right() {
        let ir = lower("builtins.compareVersions 1 (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let left = args[0];
        let left_span = ir.arena.node(left).expect("left argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("compareVersions type-checks left first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: left,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), left_span);

        let ir = lower("builtins.compareVersions \"1\" 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let right = args[1];
        let right_span = ir.arena.node(right).expect("right argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("compareVersions type-checks right second");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: right,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), right_span);
    }

    #[test]
    fn compare_versions_primop_rejects_string_context() {
        let ir = lower("builtins.compareVersions \"1\" \"2\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let left = args[0];
        let right = args[1];
        let left_span = ir.arena.node(left).expect("left argument exists").span;
        let right_span = ir.arena.node(right).expect("right argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let left_value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"1".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing string allocates");
        let right_value = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"2".to_vec()))
            .expect("context-free string allocates");

        let error = evaluator
            .eval_compare_versions_values(
                left,
                left_span,
                left_value,
                right,
                right_span,
                right_value,
            )
            .expect_err("compareVersions rejects string context");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextNotAllowed {
                id: left,
                op: "compareVersions",
            }
        );
        assert_eq!(error.span(), left_span);
    }

    #[test]
    fn base_name_and_dir_of_primops_force_and_coerce_arguments() {
        let ir = lower("builtins.baseNameOf (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("baseNameOf forces its argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );
        assert_eq!(error.span(), argument_span);

        let ir = lower("builtins.dirOf 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("integer is not string-coercible here");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn strict_unary_primops_force_arguments() {
        let ir = lower("builtins.isInt (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("predicate forces argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn break_result_is_forced_when_explicitly_demanded() {
        let ir = lower("builtins.break (1 / 0)");
        let mut evaluator = TreeWalk::new(&ir);
        let value = evaluator
            .eval_root()
            .expect("break returns the argument thunk");

        assert!(value.is_thunk());

        let error = evaluator
            .force_value(ir.root, Span::new(0, 0), value)
            .expect_err("forcing the returned thunk demands the argument");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn break_thunks_can_be_forced_by_arithmetic_and_reused() {
        assert_eq!(
            eval("builtins.add (builtins.break (1 + 2)) 1").as_int(),
            Ok(4)
        );
        assert_eq!(
            eval("let add = builtins.add; in add (builtins.break (1 + 2)) 1").as_int(),
            Ok(4)
        );
        assert!(matches!(
            eval_whnf(&lower(
                "builtins.add (builtins.break (builtins.break (1 + 2))) 1"
            ))
            .expect_err("arithmetic demands through exactly one break wrapper")
            .kind(),
            TreeWalkErrorKind::Type {
                actual: ValueTag::Thunk,
                ..
            }
        ));
        assert_eq!(
            eval("builtins.isInt (builtins.break (1 + 2))").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval(
                "let x = builtins.break (1 + 2); y = builtins.add x 0; \
                 in y + (if builtins.isInt x then 1 else 2)"
            )
            .as_int(),
            Ok(4)
        );
        assert_eq!(
            eval("builtins.seq (builtins.break (1 / 0)) 7").as_int(),
            Ok(7)
        );
        assert_eq!(
            eval("builtins.deepSeq (builtins.break [ (1 / 0) ]) 7").as_int(),
            Ok(7)
        );
        assert_eq!(
            eval("let s = builtins.seq; in s (builtins.break (1 / 0)) 7").as_int(),
            Ok(7)
        );
        assert_eq!(
            eval("let x = builtins.break [ 1 2 ]; y = builtins.seq x 0; in y + builtins.length x")
                .as_int(),
            Ok(2)
        );
        assert_eq!(
            eval(
                "let x = builtins.break { a = 1; }; y = builtins.deepSeq x 0; \
                 in y + (if builtins.hasAttr \"a\" x then 1 else 2)"
            )
            .as_int(),
            Ok(1)
        );
        assert_eq!(eval("(builtins.break (1 + 2)) == 3").as_bool(), Ok(true));
        assert_eq!(
            eval("(builtins.break (builtins.break (1 + 2))) == 3").as_bool(),
            Ok(false)
        );
        assert_eq!(eval("(builtins.break [ 1 ]) == [ 1 ]").as_bool(), Ok(true));
        assert_eq!(
            eval_string_bytes("builtins.break (\"a\" + \"b\") + \"c\""),
            b"abc"
        );
        assert!(matches!(
            eval_whnf(&lower("(builtins.break (1 + 2)) + 1"))
                .expect_err("operator + does not treat break like builtins.add")
                .kind(),
            TreeWalkErrorKind::Type { .. }
        ));
        assert_eq!(
            eval("builtins.length ((builtins.break ([ 1 ] ++ [ 2 ])) ++ [ 3 ])").as_int(),
            Ok(3)
        );
        assert_eq!(
            eval("let x = builtins.break (1 + 2); in -x").as_int(),
            Ok(-3)
        );
        assert!(matches!(
            eval_whnf(&lower("(builtins.break (x: x)) 1"))
                .expect_err("direct break lambda remains a thunk"),
            TreeWalkError {
                kind: TreeWalkErrorKind::Type {
                    actual: ValueTag::Thunk,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            eval("let f = builtins.break (x: x); in f 1").as_int(),
            Ok(1)
        );
        assert!(matches!(
            eval_whnf(&lower(
                "let f = builtins.break (builtins.break (x: x)); in f 1"
            ))
            .expect_err("double break lambda leaves one thunk"),
            TreeWalkError {
                kind: TreeWalkErrorKind::Type {
                    actual: ValueTag::Thunk,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn break_preserves_path_arguments_as_paths() {
        let (_dir, path) = temp_file_with_bytes("break-path", b"abc");
        let path = path_source(&path);

        assert_eq!(
            eval(&format!("builtins.isPath (builtins.break {path})")).as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval_string_bytes(&format!("builtins.typeOf (builtins.break {path})")),
            b"path"
        );
        assert_eq!(
            eval(&format!(
                "let f = builtins.break; in builtins.isPath (f {path})"
            ))
            .as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn get_env_primop_reads_configured_environment() {
        assert_eq!(eval_string_bytes("builtins.getEnv \"HOME\""), b"");
        assert_eq!(
            eval_string_bytes("builtins.typeOf (builtins.getEnv \"HOME\")"),
            b"string"
        );
        assert_eq!(
            eval_string_bytes_with_options(
                "builtins.getEnv \"HOME\"",
                TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec())
            ),
            b"/home/aos"
        );
        assert_eq!(
            eval_string_bytes_with_options(
                "let f = builtins.getEnv; in f \"HOME\"",
                TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec())
            ),
            b"/home/aos"
        );
        assert_eq!(
            eval_string_bytes_with_options(
                "builtins.getEnv \"MISSING\"",
                TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec())
            ),
            b""
        );
    }

    #[test]
    fn get_env_primop_type_checks_argument() {
        let ir = lower("builtins.getEnv 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf_owned(&ir).expect_err("getEnv requires a string");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: argument,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn get_env_primop_rejects_context_bearing_names() {
        let ir = lower("builtins.getEnv \"HOME\"");
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("getEnv argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::with_options(
            &ir,
            TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/home/aos".to_vec()),
        );
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                b"HOME".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing string allocates");

        let error = evaluator
            .eval_get_env_primop(ir.root, root.span, argument, argument_span, value)
            .expect_err("getEnv rejects string context");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextNotAllowed {
                id: argument,
                op: "getEnv",
            }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn read_file_primop_reads_file_contents() {
        let dir = unique_temp_dir("read-file");
        let path = dir.join("data.txt");
        let contents = b"hello\xff\n";
        fs::write(&path, contents).expect("file writes");
        let path = path_source(&path);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).expect("symlink creates");
        let link_path = path_source(&link);

        assert_eq!(
            eval_string_bytes(&format!("builtins.readFile {}", nix_string_literal(&path))),
            contents
        );
        assert_eq!(
            eval_string_bytes(&format!("builtins.readFile {path}")),
            contents
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "builtins.readFile {}",
                nix_string_literal(&link_path)
            )),
            contents
        );
        assert_eq!(
            eval_string_bytes(&format!(
                "let f = builtins.readFile; in f {}",
                nix_string_literal(&path)
            )),
            contents
        );
        assert_eq!(
            eval_string_bytes(
                "let builtins = { readFile = path: \"local\"; }; in builtins.readFile \"relative.txt\""
            ),
            b"local"
        );

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn read_file_primop_returns_context_free_strings() {
        let (dir, path) = temp_file_with_bytes(
            "read-file-context-free",
            b"/nix/store/00000000000000000000000000000000-name\n",
        );
        let path = path_source(&path);

        assert_eq!(
            eval(&format!(
                "builtins.hasContext (builtins.readFile {})",
                nix_string_literal(&path)
            ))
            .as_bool(),
            Ok(false)
        );

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn read_file_primop_rejects_relative_strings() {
        let ir = lower("builtins.readFile \"relative.txt\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let path = args[0];
        let path_span = ir.arena.node(path).expect("path exists").span;

        let error = eval_whnf_owned(&ir).expect_err("relative strings are rejected");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::PathNotAbsolute {
                id: path,
                path: b"relative.txt".to_vec(),
            }
        );
        assert_eq!(error.span(), path_span);
    }

    #[test]
    fn read_file_primop_rejects_context_bearing_path_strings() {
        let (dir, path) = temp_file_with_bytes("read-file-context-path", b"data");
        let path = path_source(&path);
        let ir = lower(&format!("builtins.readFile {}", nix_string_literal(&path)));
        let root = *ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let argument = ir
            .arena
            .child_slice(args)
            .expect("primop args exist")
            .first()
            .copied()
            .expect("readFile argument exists");
        let argument_span = ir.arena.node(argument).expect("argument exists").span;
        let mut evaluator = TreeWalk::new(&ir);
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let value = evaluator
            .heap
            .alloc_string(NixString::new(
                path.as_bytes().to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("context-bearing path allocates");

        let error = evaluator
            .eval_read_file_primop(ir.root, root.span, argument, argument_span, value)
            .expect_err("readFile rejects string context");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::StringContextNotAllowed {
                id: argument,
                op: "readFile",
            }
        );
        assert_eq!(error.span(), argument_span);

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn read_file_primop_is_strict_in_path_argument() {
        let ir = lower("builtins.readFile (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("readFile forces path argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn read_file_primop_reports_file_read_errors() {
        let dir = unique_temp_dir("read-file-missing");
        let path = path_source(&dir.join("missing.txt"));
        let ir = lower(&format!("builtins.readFile {}", nix_string_literal(&path)));
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let path_id = args[0];
        let path_span = ir.arena.node(path_id).expect("path exists").span;

        let error = eval_whnf_owned(&ir).expect_err("missing file is reported");

        match error.kind() {
            TreeWalkErrorKind::FileRead {
                id,
                path: actual,
                message,
            } => {
                assert_eq!(id, path_id);
                assert_eq!(actual.as_slice(), path.as_bytes());
                assert!(!message.is_empty());
            }
            other => panic!("expected file-read error, got {other:?}"),
        }
        assert_eq!(error.span(), path_span);

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn read_file_primop_reports_directory_read_errors() {
        let dir = unique_temp_dir("read-file-directory");
        let path = path_source(&dir);
        let ir = lower(&format!("builtins.readFile {}", nix_string_literal(&path)));
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let path_id = args[0];
        let path_span = ir.arena.node(path_id).expect("path exists").span;

        let error = eval_whnf_owned(&ir).expect_err("directory read is reported");

        match error.kind() {
            TreeWalkErrorKind::FileRead {
                id,
                path: actual,
                message,
            } => {
                assert_eq!(id, path_id);
                assert_eq!(actual.as_slice(), path.as_bytes());
                assert!(!message.is_empty());
            }
            other => panic!("expected file-read error, got {other:?}"),
        }
        assert_eq!(error.span(), path_span);

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn read_file_primop_rejects_nul_bytes() {
        let (dir, path) = temp_file_with_bytes("read-file-nul", b"a\0b");
        let path = path_source(&path);
        let ir = lower(&format!("builtins.readFile {}", nix_string_literal(&path)));
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let path_id = args[0];
        let path_span = ir.arena.node(path_id).expect("path exists").span;

        let error = eval_whnf_owned(&ir).expect_err("NUL bytes are rejected");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::FileReadContainsNul {
                id: path_id,
                path: path.as_bytes().to_vec(),
            }
        );
        assert_eq!(error.span(), path_span);

        fs::remove_dir_all(dir).expect("temp directory removes");
    }

    #[test]
    fn unsupported_strict_primops_force_arguments_before_reporting_unsupported() {
        let ir = lower("builtins.import (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("root is a primop");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        let argument = args[0];
        let argument_span = ir.arena.node(argument).expect("argument exists").span;

        let error = eval_whnf(&ir).expect_err("unsupported primop still forces argument");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: argument }
        );
        assert_eq!(error.span(), argument_span);
    }

    #[test]
    fn unsupported_primops_report_symbol_and_span() {
        let ir = lower("builtins.import \"/tmp/aos-nix-missing-import.nix\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::PrimOp { symbol, .. } = root.data else {
            panic!("root is a primop");
        };

        let error = eval_whnf_owned(&ir).expect_err("import remains unsupported");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedPrimOp {
                id: ir.root,
                symbol,
            }
        );
        assert_eq!(error.span(), root.span);
    }

    #[test]
    fn interpolation_coerces_attrsets_with_to_string_before_out_path() {
        assert_eq!(
            eval_string_bytes("\"${{ __toString = self: self.name; name = \"custom\"; }}\""),
            b"custom"
        );
        assert_eq!(
            eval_string_bytes("\"pre-${{ outPath = \"store\"; }}-post\""),
            b"pre-store-post"
        );
        assert_eq!(
            eval_string_bytes("\"${{ __toString = self: \"hook\"; outPath = 1 / 0; }}\""),
            b"hook"
        );
        assert_eq!(
            eval_string_bytes("\"${{ __toString = self: { outPath = \"nested\"; }; }}\""),
            b"nested"
        );
        assert_eq!(
            eval_string_bytes("\"${{ outPath = { outPath = \"nested\"; }; }}\""),
            b"nested"
        );
    }

    #[test]
    fn dynamic_attr_names_use_string_coercion() {
        assert_eq!(
            eval("{ ${ { outPath = \"name\"; } } = 7; }.name").as_int(),
            Ok(7)
        );
        assert_eq!(
            eval("{ value = 9; }.${ { __toString = self: \"value\"; } }").as_int(),
            Ok(9)
        );
    }

    #[test]
    fn interpolation_rejects_non_coercible_values() {
        let cases = [
            ("\"${1}\"", ValueTag::Int),
            ("\"${true}\"", ValueTag::Bool),
            ("\"${null}\"", ValueTag::Null),
            ("\"${[]}\"", ValueTag::List),
            ("\"${{}}\"", ValueTag::Attrs),
        ];

        for (source, actual) in cases {
            let ir = lower(source);
            let error = eval_whnf_owned(&ir).expect_err("value is not interpolable");
            let TreeWalkErrorKind::Type {
                expected,
                actual: observed,
                ..
            } = error.kind()
            else {
                panic!("expected type error for {source}");
            };
            assert_eq!(expected, "string");
            assert_eq!(observed, actual);
        }
    }

    #[test]
    fn interpolation_requires_to_string_results_to_be_strings() {
        let ir = lower("\"${{ __toString = self: 1; }}\"");
        let error = eval_whnf_owned(&ir).expect_err("__toString result must be a string");
        let TreeWalkErrorKind::Type {
            expected, actual, ..
        } = error.kind()
        else {
            panic!("expected type error for non-string __toString result");
        };
        assert_eq!(expected, "string");
        assert_eq!(actual, ValueTag::Int);

        let ir = lower("\"${{ __toString = \"bad\"; outPath = \"fallback\"; }}\"");
        let error = eval_whnf_owned(&ir).expect_err("__toString takes precedence over outPath");
        let TreeWalkErrorKind::Type {
            expected, actual, ..
        } = error.kind()
        else {
            panic!("expected type error for non-lambda __toString");
        };
        assert_eq!(expected, "lambda");
        assert_eq!(actual, ValueTag::String);

        let ir = lower("\"${{ __toString = self: {}; outPath = \"fallback\"; }}\"");
        let error = eval_whnf_owned(&ir).expect_err("bad __toString result does not fall back");
        let TreeWalkErrorKind::Type {
            expected, actual, ..
        } = error.kind()
        else {
            panic!("expected type error for non-coercible __toString result");
        };
        assert_eq!(expected, "string");
        assert_eq!(actual, ValueTag::Attrs);
    }

    #[test]
    fn evaluates_empty_list_literals_with_owned_heap() {
        let ir = lower("[]");
        let outcome = eval_whnf_owned(&ir).expect("empty list evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::List);
        assert!(
            outcome
                .heap()
                .get_list(value)
                .expect("list is heap-owned")
                .is_empty()
        );
    }

    #[test]
    fn evaluates_non_empty_list_literals_with_lazy_elements() {
        let ir = lower("[ true (1 / 0) \"s\" ]");
        let outcome = eval_whnf_owned(&ir).expect("non-empty list evaluates");
        let value = outcome.value();
        let heap = outcome.heap();
        let list = heap.get_list(value).expect("list is heap-owned");

        assert_eq!(value.tag(), ValueTag::List);
        assert_eq!(list.len(), 3);
        assert_eq!(list.get(0).expect("first").as_bool(), Ok(true));

        let lazy_division = list.get(1).expect("second");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("list element thunk is heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );

        let string = list.get(2).expect("third");
        assert_eq!(
            heap.get_string(string)
                .expect("string element is heap-owned")
                .bytes(),
            b"s"
        );
    }

    #[test]
    fn list_element_thunks_capture_let_environments() {
        let ir = lower("let x = 1 + 2; in [ x ]");
        let outcome = eval_whnf_owned(&ir).expect("list evaluates");
        let heap = outcome.heap();
        let list = heap.get_list(outcome.value()).expect("list is heap-owned");
        let element = list.get(0).expect("first");
        let element_thunk = heap
            .get_thunk(element)
            .expect("list element thunk is heap-owned");

        assert_eq!(
            element_thunk.env().expect("node thunk env").frames().len(),
            1
        );
        let captured_x = element_thunk.env().expect("node thunk env").frames()[0]
            .get(0)
            .expect("captured frame slot exists");
        assert_eq!(captured_x.tag(), ValueTag::Thunk);
        let x_thunk = heap
            .get_thunk(captured_x)
            .expect("captured binding thunk is heap-owned");
        assert_eq!(x_thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(x_thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn list_concat_concatenates_empty_lists() {
        let ir = lower("[] ++ []");
        let outcome = eval_whnf_owned(&ir).expect("list concat evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::List);
        assert!(
            outcome
                .heap()
                .get_list(value)
                .expect("concat result is heap-owned")
                .is_empty()
        );
    }

    #[test]
    fn list_concat_concatenates_non_empty_lists_without_forcing_elements() {
        let ir = lower("[ (1 / 0) ] ++ [ true ]");
        let outcome = eval_whnf_owned(&ir).expect("list concat evaluates");
        let heap = outcome.heap();
        let list = heap
            .get_list(outcome.value())
            .expect("concat result is heap-owned");

        assert_eq!(list.len(), 2);
        let lazy_division = list.get(0).expect("first");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("left element thunk is heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
        assert_eq!(list.get(1).expect("second").as_bool(), Ok(true));
    }

    #[test]
    fn list_concat_preserves_spine_values_without_forcing_elements() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = *ir.arena.node(ir.root).expect("root exists");
        let left_ptr = NonNull::new(8usize as *mut HeapObject).expect("non-null pointer");
        let right_ptr = NonNull::new(16usize as *mut HeapObject).expect("non-null pointer");
        let left_thunk = Value::thunk(left_ptr).expect("left thunk pointer is aligned");
        let right_thunk = Value::thunk(right_ptr).expect("right thunk pointer is aligned");
        let left = evaluator
            .heap
            .alloc_list(NixList::new(vec![Value::int(1), left_thunk]))
            .expect("left list allocates");
        let right = evaluator
            .heap
            .alloc_list(NixList::new(vec![right_thunk, Value::bool(true)]))
            .expect("right list allocates");

        let result = evaluator
            .concat_lists(ir.root, &node, left, right)
            .expect("lists concatenate");
        let list = evaluator
            .heap
            .get_list(result)
            .expect("result list is heap-owned");

        assert_eq!(list.len(), 4);
        assert_eq!(list.get(0).expect("first").as_int(), Ok(1));
        assert!(list.get(1).expect("second").raw_eq(left_thunk));
        assert!(list.get(2).expect("third").raw_eq(right_thunk));
        assert_eq!(list.get(3).expect("fourth").as_bool(), Ok(true));
    }

    #[test]
    fn attr_update_merges_shallowly_with_rhs_precedence() {
        assert_eq!(
            eval("let r = { a = 1; } // { b = 2; }; in r.a + r.b").as_int(),
            Ok(3)
        );
        assert_eq!(eval("(({ a = 1 / 0; } // { a = 2; }).a)").as_int(), Ok(2));
        assert_eq!(
            eval("(({ a = { x = 1; }; } // { a = { y = 2; }; }).a.x or 9)").as_int(),
            Ok(9)
        );
    }

    #[test]
    fn attr_update_keeps_values_lazy() {
        assert_eq!(
            eval("let r = { a = 1; } // { b = 1 / 0; }; in r.a").as_int(),
            Ok(1)
        );

        let ir = lower("{ a = 1 / 0; } // { b = 2; }");
        let a = symbol_for(&ir, b"a");
        let b = symbol_for(&ir, b"b");
        let outcome = eval_whnf_owned(&ir).expect("attr update evaluates");
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("update result is heap-owned");

        assert_eq!(attrs.get(b).expect("b exists").as_int(), Ok(2));
        let lazy_division = attrs.get(a).expect("a exists");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = outcome
            .heap()
            .get_thunk(lazy_division)
            .expect("left attr value stays lazy");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    }

    #[test]
    fn evaluates_empty_attrsets_with_owned_heap() {
        let ir = lower("{}");
        let outcome = eval_whnf_owned(&ir).expect("empty attrset evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::Attrs);
        assert!(
            outcome
                .heap()
                .get_attrs(value)
                .expect("attrset is heap-owned")
                .is_empty()
        );
    }

    #[test]
    fn evaluates_static_attrsets_with_lazy_values() {
        let ir = lower("{ a = 1; b = (1 / 0); }");
        let a = symbol_for(&ir, b"a");
        let b = symbol_for(&ir, b"b");
        let outcome = eval_whnf_owned(&ir).expect("static attrset evaluates");
        let heap = outcome.heap();
        let attrs = heap
            .get_attrs(outcome.value())
            .expect("attrset is heap-owned");

        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs.get(a).expect("a exists").as_int(), Ok(1));

        let lazy_division = attrs.get(b).expect("b exists");
        assert_eq!(lazy_division.tag(), ValueTag::Thunk);
        let thunk = heap
            .get_thunk(lazy_division)
            .expect("attr value thunk is heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(
            ir.arena
                .node(thunk.body().expect("thunk body exists"))
                .expect("thunk body exists")
                .kind,
            IrKind::BinOp
        );
    }

    #[test]
    fn evaluates_static_recursive_attrsets_with_lazy_self_scope() {
        assert_eq!(eval("(rec { a = 1; b = a + 2; }).b").as_int(), Ok(3));
        assert_eq!(eval("(rec { a = b; b = 1; }).a").as_int(), Ok(1));
        assert_eq!(eval("(rec { a = 1 / 0; }).b or 2").as_int(), Ok(2));

        let ir = lower("(rec { a = a; }).a");
        let error = eval_whnf(&ir).expect_err("recursive attr self-reference blackholes");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Force {
                source: ForceError::InfiniteRecursion,
                ..
            }
        ));
    }

    #[test]
    fn forcing_attr_value_thunks_memoizes_whnf_results() {
        let ir = lower("{ a = 1 + 2; }");
        let a = symbol_for(&ir, b"a");
        let mut evaluator = TreeWalk::new(&ir);
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };

        assert_eq!(thunk_value.tag(), ValueTag::Thunk);
        assert_eq!(
            evaluator
                .heap()
                .get_thunk(thunk_value)
                .expect("thunk exists")
                .cell()
                .state(),
            Ok(ThunkState::Suspended)
        );

        let forced = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("thunk force succeeds");
        assert_eq!(forced.as_int(), Ok(3));
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("thunk remains heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));
        let cached = thunk
            .cell()
            .cached_value()
            .expect("forced thunk has cached value")
            .expect("cached value exists");
        assert!(cached.raw_eq(Value::int(3)));

        let forced_again = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect("forced thunk reuses cache");
        assert_eq!(forced_again.as_int(), Ok(3));
    }

    #[test]
    fn strict_operand_evaluation_forces_direct_thunk_alloc_results() {
        let body = IrId::new(0);
        let lhs = IrId::new(1);
        let rhs = IrId::new(2);
        let root = IrId::new(3);
        let ir = manual_ir(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(IrKind::ThunkAlloc, Span::new(0, 1), IrData::Node(body)),
                pure_node(IrKind::Int, Span::new(4, 5), IrData::Int(2)),
                pure_node(
                    IrKind::BinOp,
                    Span::new(0, 5),
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs,
                        rhs,
                    },
                ),
            ],
        );

        assert_eq!(
            eval_whnf(&ir)
                .expect("strict operand thunk is forced")
                .as_int(),
            Ok(3)
        );
    }

    #[test]
    fn forcing_errors_reset_thunks_to_suspended() {
        let ir = lower("{ a = 1 / 0; }");
        let a = symbol_for(&ir, b"a");
        let mut evaluator = TreeWalk::new(&ir);
        let root = evaluator.eval_root().expect("attrset evaluates");
        let thunk_value = {
            let attrs = evaluator
                .heap()
                .get_attrs(root)
                .expect("attrset is heap-owned");
            attrs.get(a).expect("a exists")
        };
        let error = evaluator
            .force_value(ir.root, Span::new(0, 0), thunk_value)
            .expect_err("division by zero remains a force error");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
        let thunk = evaluator
            .heap()
            .get_thunk(thunk_value)
            .expect("thunk remains heap-owned");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert!(
            thunk
                .cell()
                .cached_value()
                .expect("suspended thunk has no invalid state")
                .is_none()
        );
    }

    #[test]
    fn evaluates_dynamic_attrsets_with_string_keys_and_null_omission() {
        assert_eq!(
            eval("let name = \"a\"; in { ${name} = 1; }.${name}").as_int(),
            Ok(1)
        );
        assert_eq!(eval("({ ${\"a\" + \"b\"} = 3; }).ab").as_int(), Ok(3));
        assert_eq!(eval("rec { ${\"a\"} = b; b = 2; }.a").as_int(), Ok(2));
        assert_eq!(
            eval("let a = 7; in rec { ${\"x\"} = a; a = 1; }.x").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval(
                "let x = \"x\"; y = \"outer\"; in rec { ${y} = 1; a = \"bar\"; b = \"baz\"; }.outer"
            )
            .as_int(),
            Ok(1)
        );
        assert_eq!(eval("{ ${null} = 1 / 0; a = 2; }.a").as_int(), Ok(2));

        let skipped = lower("{ ${null} = 1 / 0; }");
        let outcome = eval_whnf_owned(&skipped).expect("null dynamic key is skipped");
        assert!(
            outcome
                .heap()
                .get_attrs(outcome.value())
                .expect("attrset is heap-owned")
                .is_empty()
        );
    }

    #[test]
    fn dynamic_attrsets_report_duplicate_and_non_string_keys() {
        let duplicate = lower("{ ${\"a\"} = 1; a = 2; }");
        let duplicate_symbol = symbol_for(&duplicate, b"a");
        let duplicate_error =
            eval_whnf_owned(&duplicate).expect_err("computed duplicate key is invalid");
        assert_eq!(
            duplicate_error.kind(),
            TreeWalkErrorKind::Attr {
                id: duplicate.root,
                source: AttrError::DuplicateKey {
                    key: duplicate_symbol
                },
            }
        );

        let non_string = lower("{ ${1} = 1; }");
        let expression = non_string
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| node.kind == IrKind::Int && node.data == IrData::Int(1))
            .map(|(index, _)| IrId::new(index as u32))
            .expect("dynamic key expression exists");
        let error = eval_whnf_owned(&non_string).expect_err("dynamic key must be string or null");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: expression,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(
            error.span(),
            non_string
                .arena
                .node(expression)
                .expect("dynamic key expression exists")
                .span
        );
    }

    #[test]
    fn let_bindings_are_lazy_and_self_visible() {
        assert_eq!(eval("let x = 1 + 2; in x").as_int(), Ok(3));
        assert_eq!(eval("let a = 1; b = 2; in a + b").as_int(), Ok(3));
        assert_eq!(
            eval("let a = 1; b = 2; in let c = a + b; in c").as_int(),
            Ok(3)
        );
        assert_eq!(eval("let x = 1 / 0; in 7").as_int(), Ok(7));
        assert_eq!(eval("let p = ./foo; in 7").as_int(), Ok(7));

        let ir = lower("let x = x; in x");
        let error = eval_whnf(&ir).expect_err("self-recursive let blackholes");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::Force {
                source: ForceError::InfiniteRecursion,
                ..
            }
        ));
    }

    #[test]
    fn let_environment_captures_survive_escaping_thunks() {
        assert_eq!(eval("(let x = 1 + 2; in { a = x; }).a").as_int(), Ok(3));
        assert_eq!(eval("let x = 1; in let y = x + 2; in y").as_int(), Ok(3));
    }

    #[test]
    fn simple_lambdas_apply_with_lazy_arguments() {
        assert_eq!(eval("(x: x + 1) 2").as_int(), Ok(3));
        assert_eq!(eval("let f = x: x; in f (1 + 2)").as_int(), Ok(3));
        assert_eq!(eval("let f = x: 7; in f (1 / 0)").as_int(), Ok(7));
        assert_eq!(eval("let x = 1; f = y: x + y; in f 2").as_int(), Ok(3));
        assert_eq!(
            eval("let x = 1; f = y: x + y; in let x = 10; in f x").as_int(),
            Ok(11)
        );
        assert_eq!(eval("((x: y: x) (1 + 2)) 0").as_int(), Ok(3));
    }

    #[test]
    fn with_scopes_probe_dynamic_attrs_lazily() {
        assert_eq!(eval("with { a = 1; }; a").as_int(), Ok(1));
        assert_eq!(eval("with { f = x: x + 1; }; f 2").as_int(), Ok(3));
        assert_eq!(eval("with (1 / 0); 7").as_int(), Ok(7));
        assert_eq!(eval("with { a = 1 / 0; }; 7").as_int(), Ok(7));
        assert_eq!(eval("with { a = 1; }; with { a = 2; }; a").as_int(), Ok(2));
        assert_eq!(eval("let a = 3; in with { a = 1; }; a").as_int(), Ok(3));
        assert_eq!(eval("with { true = 1; }; true").as_int(), Ok(1));
        assert_eq!(eval("with {}; true").as_bool(), Ok(true));
        assert_eq!(eval("with {}; false").as_bool(), Ok(false));
        assert_eq!(eval("with {}; null").tag(), ValueTag::Null);
    }

    #[test]
    fn with_scopes_capture_lexical_environments() {
        assert_eq!(
            eval("let x = 1; f = y: with { a = x + y; }; a; in let x = 10; in f x").as_int(),
            Ok(11)
        );
        assert_eq!(
            eval("let x = 1; scope = { a = x; }; f = y: with scope; a + y; in f 2").as_int(),
            Ok(3)
        );
        assert_eq!(
            eval("let f = with { a = 1; }; x: a + x; in f 2").as_int(),
            Ok(3)
        );
        assert_eq!(eval("(with { a = 1 + 2; }; { b = a; }).b").as_int(), Ok(3));
    }

    #[test]
    fn with_lookup_reports_non_attr_scopes_and_missing_names() {
        let non_attr = lower("with 1; missing");
        let root = non_attr.arena.node(non_attr.root).expect("root exists");
        let IrData::Pair { first, .. } = root.data else {
            panic!("with root has pair payload");
        };
        let first_span = non_attr.arena.node(first).expect("scope exists").span;
        let error = eval_whnf(&non_attr).expect_err("non-attr with scope is invalid on lookup");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: first,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), first_span);

        let missing = lower("with {}; missing");
        let IrData::Pair {
            second: missing_var,
            ..
        } = missing
            .arena
            .node(missing.root)
            .expect("missing root exists")
            .data
        else {
            panic!("with root has pair payload");
        };
        let missing_symbol = symbol_for(&missing, b"missing");
        let error = eval_whnf(&missing).expect_err("missing with name remains unresolved");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnresolvedWithVar {
                id: missing_var,
                symbol: missing_symbol,
            }
        );
    }

    #[test]
    fn formal_set_lambdas_bind_attrs_defaults_ellipsis_and_aliases() {
        assert_eq!(eval("({ x }: x) { x = 1; }").as_int(), Ok(1));
        assert_eq!(eval("({ x, y }: x + y) { x = 1; y = 2; }").as_int(), Ok(3));
        assert_eq!(
            eval("({ x, ... }: x) { x = 1; y = 1 / 0; }").as_int(),
            Ok(1)
        );
        assert_eq!(eval("({ x ? 1 + 2 }: x) {}").as_int(), Ok(3));
        assert_eq!(eval("({ x ? 1 / 0 }: 7) {}").as_int(), Ok(7));
        assert_eq!(eval("({ x ? 1 / 0 }: x) { x = 7; }").as_int(), Ok(7));
        assert_eq!(eval("({ a, b ? a + 1 }: b) { a = 2; }").as_int(), Ok(3));
        assert_eq!(
            eval("(args@{ x, ... }: args.x) { x = 1; y = 2; }").as_int(),
            Ok(1)
        );
        assert_eq!(
            eval("({ x, ... }@args: args.y) { x = 1; y = 2; }").as_int(),
            Ok(2)
        );
        assert_eq!(eval("({ x ? 1 }@args: args ? x) {}").as_bool(), Ok(false));
        assert_eq!(
            eval("({ x ? 1 }@args: args ? x) { x = 2; }").as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn formal_set_lambdas_report_match_errors() {
        let missing = lower("({ x }: x) {}");
        let missing_symbol = symbol_for(&missing, b"x");
        let error = eval_whnf(&missing).expect_err("required formal is missing");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::MissingFormalAttribute {
                id: missing.root,
                symbol: missing_symbol,
            }
        );

        let extra = lower("({ x }: x) { x = 1; z = 2; a = 3; }");
        let extra_symbol = symbol_for(&extra, b"a");
        let error = eval_whnf(&extra).expect_err("extra attr without ellipsis is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnexpectedFormalAttribute {
                id: extra.root,
                symbol: extra_symbol,
            }
        );

        let non_attr = lower("({ x }: x) 1");
        let root = non_attr.arena.node(non_attr.root).expect("root exists");
        let IrData::Pair { second, .. } = root.data else {
            panic!("application root has pair payload");
        };
        let second_span = non_attr.arena.node(second).expect("argument exists").span;
        let error = eval_whnf(&non_attr).expect_err("formal-set argument must be attrs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: second,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), second_span);
    }

    #[test]
    fn function_application_requires_lambda_functions() {
        let ir = lower("1 2");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Pair { first, .. } = root.data else {
            panic!("application root has pair payload");
        };
        let first_span = ir.arena.node(first).expect("function exists").span;
        let error = eval_whnf(&ir).expect_err("integer is not callable");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: first,
                expected: "lambda",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), first_span);

        let manual = manual_ir(
            IrId::new(1),
            vec![
                pure_node(IrKind::Int, first_span, IrData::Int(1)),
                pure_node(
                    IrKind::Apply,
                    Span::new(0, 4),
                    IrData::Pair {
                        first: IrId::new(0),
                        second: IrId::new(99),
                    },
                ),
            ],
        );
        let manual_error =
            eval_whnf(&manual).expect_err("function type wins before lazy argument lookup");

        assert_eq!(
            manual_error.kind(),
            TreeWalkErrorKind::Type {
                id: IrId::new(0),
                expected: "lambda",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(manual_error.span(), first_span);
    }

    #[test]
    fn select_static_keys_force_lazy_values() {
        assert_eq!(eval("({ a = 1 + 2; }).a").as_int(), Ok(3));

        let ir = lower("({ a = 1 / 0; }).a");
        let error = eval_whnf_owned(&ir).expect_err("selected field thunk is forced");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn select_defaults_are_lazy_and_forced_when_missing() {
        assert_eq!(eval("({ a = 1; }).a or (1 / 0)").as_int(), Ok(1));
        assert_eq!(eval("({ a = 1; }).b or (1 + 2)").as_int(), Ok(3));
        assert_eq!(eval("({}).a.b or 2").as_int(), Ok(2));
        assert_eq!(eval("(1).a or 2").as_int(), Ok(2));
        assert_eq!(eval("({ a = 1; }).a.b or 2").as_int(), Ok(2));

        let ir = lower("({ a = 1; }).b or (1 / 0)");
        let error = eval_whnf_owned(&ir).expect_err("missing key forces default thunk");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn missing_static_select_reports_attribute() {
        let ir = lower("({}).a");
        let symbol = symbol_for(&ir, b"a");
        let error = eval_whnf_owned(&ir).expect_err("missing key without default is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::MissingAttribute {
                id: ir.root,
                symbol,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );

        let nested = lower("({ a = {}; }).a.b");
        let nested_symbol = symbol_for(&nested, b"b");
        let nested_error =
            eval_whnf_owned(&nested).expect_err("missing nested key without default is invalid");

        assert_eq!(
            nested_error.kind(),
            TreeWalkErrorKind::MissingAttribute {
                id: nested.root,
                symbol: nested_symbol,
            }
        );
        assert_eq!(
            nested_error.span(),
            nested.arena.node(nested.root).expect("root exists").span
        );
    }

    #[test]
    fn select_requires_attrset_receivers() {
        let ir = lower("(1).a");
        let error = eval_whnf(&ir).expect_err("integer receiver is not an attrset");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: ir.root,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );

        let nested = lower("({ a = 1; }).a.b");
        let nested_error =
            eval_whnf_owned(&nested).expect_err("integer intermediate is not an attrset");

        assert_eq!(
            nested_error.kind(),
            TreeWalkErrorKind::Type {
                id: nested.root,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(
            nested_error.span(),
            nested.arena.node(nested.root).expect("root exists").span
        );
    }

    #[test]
    fn select_evaluates_nested_static_and_dynamic_paths() {
        assert_eq!(eval("({ a = { b = 1 + 2; }; }).a.b").as_int(), Ok(3));
        assert_eq!(eval("({ a = 1; }).${\"a\"}").as_int(), Ok(1));
        assert_eq!(
            eval("let name = \"a\"; in { a = { b = 2; }; }.${name}.b").as_int(),
            Ok(2)
        );
        assert_eq!(eval("({}).${\"a\"}.${1 / 0} or 2").as_int(), Ok(2));
        assert_eq!(eval("(1).${\"a\"} or 2").as_int(), Ok(2));

        let error_ir = lower("({ a = 1 / 0; }).a.b or 2");
        let error = eval_whnf_owned(&error_ir).expect_err("intermediate thunk errors win");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let null_key = lower("({ a = 1; }).${null} or 2");
        let null_node = null_key
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| node.kind == IrKind::Null)
            .map(|(index, _)| IrId::new(index as u32))
            .expect("null key expression exists");
        let null_error =
            eval_whnf_owned(&null_key).expect_err("select dynamic null key is invalid");

        assert_eq!(
            null_error.kind(),
            TreeWalkErrorKind::Type {
                id: null_node,
                expected: "string",
                actual: ValueTag::Null,
            }
        );
        assert_eq!(
            null_error.span(),
            null_key
                .arena
                .node(null_node)
                .expect("null key expression exists")
                .span
        );
    }

    #[test]
    fn select_evaluates_receiver_and_reached_dynamic_keys_in_order() {
        let ir = lower("(1 / 0).${\"a\"}");
        let error = eval_whnf_owned(&ir).expect_err("receiver errors before dynamic key success");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
        let division = ir
            .arena
            .nodes()
            .iter()
            .find(|node| node.kind == IrKind::BinOp)
            .expect("division node exists");
        assert_eq!(error.span(), division.span);

        let dynamic_error = lower("({}).${1 / 0} or 2");
        let error = eval_whnf_owned(&dynamic_error)
            .expect_err("first dynamic key errors before default fallback");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn has_attr_detects_single_static_keys_without_forcing_values() {
        assert_eq!(eval("({ a = 1; } ? a)").as_bool(), Ok(true));
        assert_eq!(eval("({ a = 1; } ? z)").as_bool(), Ok(false));
        assert_eq!(eval("({ a = 1 / 0; } ? a)").as_bool(), Ok(true));
        assert_eq!(eval("({ a = 1 / 0; } ? z)").as_bool(), Ok(false));
    }

    #[test]
    fn has_attr_returns_false_for_non_attr_path_values() {
        assert_eq!(eval("(1 ? a)").as_bool(), Ok(false));
        assert_eq!(eval("({ a = 1; } ? a.b)").as_bool(), Ok(false));
    }

    #[test]
    fn has_attr_evaluates_nested_static_and_dynamic_paths() {
        assert_eq!(eval("({ a = { b = 1 / 0; }; } ? a.b)").as_bool(), Ok(true));
        assert_eq!(eval("({ a = {}; } ? a.b)").as_bool(), Ok(false));
        assert_eq!(eval("({ a = 1; } ? ${\"a\"})").as_bool(), Ok(true));
        assert_eq!(eval("({} ? ${\"a\"}.${1 / 0})").as_bool(), Ok(false));
        assert_eq!(eval("(1 ? ${\"a\"})").as_bool(), Ok(false));

        let error_ir = lower("({ a = 1 / 0; } ? a.b)");
        let error = eval_whnf_owned(&error_ir).expect_err("intermediate thunk errors win");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));

        let null_key = lower("({ a = 1; } ? ${null})");
        let null_node = null_key
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| node.kind == IrKind::Null)
            .map(|(index, _)| IrId::new(index as u32))
            .expect("null key expression exists");
        let null_error =
            eval_whnf_owned(&null_key).expect_err("has-attr dynamic null key is invalid");

        assert_eq!(
            null_error.kind(),
            TreeWalkErrorKind::Type {
                id: null_node,
                expected: "string",
                actual: ValueTag::Null,
            }
        );
        assert_eq!(
            null_error.span(),
            null_key
                .arena
                .node(null_node)
                .expect("null key expression exists")
                .span
        );
    }

    #[test]
    fn has_attr_evaluates_receiver_and_reached_dynamic_keys_in_order() {
        let ir = lower("((1 / 0) ? ${\"a\"})");
        let error = eval_whnf_owned(&ir).expect_err("receiver errors before dynamic key success");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
        let division = ir
            .arena
            .nodes()
            .iter()
            .find(|node| node.kind == IrKind::BinOp)
            .expect("division node exists");
        assert_eq!(error.span(), division.span);

        let dynamic_error = lower("({} ? ${1 / 0})");
        let error = eval_whnf_owned(&dynamic_error)
            .expect_err("first dynamic has-attr key is still evaluated");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn list_concat_type_checks_operands_left_to_right() {
        let lhs_ir = lower("1 ++ (1 / 0)");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("concat root has binary payload");
        };
        let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf_owned(&lhs_ir).expect_err("integer lhs is invalid before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), lhs_span);

        let rhs_ir = lower("[] ++ 1");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("concat root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_ir).expect_err("integer rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "list",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let rhs_error_ir = lower("[] ++ (1 / 0)");
        let root = rhs_error_ir
            .arena
            .node(rhs_error_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("concat root has binary payload");
        };
        let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn attr_update_type_checks_operands_left_to_right() {
        let lhs_ir = lower("1 // (1 / 0)");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("update root has binary payload");
        };
        let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf_owned(&lhs_ir).expect_err("integer lhs is invalid before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), lhs_span);

        let rhs_ir = lower("{} // 1");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("update root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_ir).expect_err("integer rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "attrs",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let rhs_error_ir = lower("{} // (1 / 0)");
        let root = rhs_error_ir
            .arena
            .node(rhs_error_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("update root has binary payload");
        };
        let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn non_owning_eval_rejects_list_concat_heap_values() {
        let ir = lower("[] ++ []");
        let error = eval_whnf(&ir).expect_err("list concat value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: ValueTag::List,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn non_owning_eval_rejects_attr_update_heap_values() {
        let ir = lower("{} // {}");
        let error = eval_whnf(&ir).expect_err("attr update value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: ValueTag::Attrs,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn string_add_concatenates_heap_strings() {
        let outcome = eval_whnf_owned(&lower("\"a\" + \"b\"")).expect("string add evaluates");
        let value = outcome.value();

        assert_eq!(value.tag(), ValueTag::String);
        assert_eq!(
            outcome
                .heap()
                .get_string(value)
                .expect("string add result is heap-owned")
                .bytes(),
            b"ab"
        );

        let escaped =
            eval_whnf_owned(&lower("\"a\\n\" + \"b\"")).expect("escaped string add evaluates");
        assert_eq!(
            escaped
                .heap()
                .get_string(escaped.value())
                .expect("escaped add result is heap-owned")
                .bytes(),
            b"a\nb"
        );
    }

    #[test]
    fn string_add_unions_contexts() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = *ir.arena.node(ir.root).expect("root exists");
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let output =
            ContextElement::single_output(b"/nix/store/derivation.drv".to_vec(), b"out".to_vec())
                .expect("output context is valid");
        let left = evaluator
            .heap
            .alloc_string(NixString::new(
                b"hello".to_vec(),
                StringContext::singleton(source.clone()).expect("source context allocates"),
            ))
            .expect("left string allocates");
        let right = evaluator
            .heap
            .alloc_string(NixString::new(
                b" world".to_vec(),
                StringContext::singleton(output.clone()).expect("output context allocates"),
            ))
            .expect("right string allocates");

        let result = evaluator
            .concat_strings(ir.root, &node, left, right)
            .expect("strings concatenate");
        let string = evaluator
            .heap
            .get_string(result)
            .expect("result string is heap-owned");

        assert_eq!(string.bytes(), b"hello world");
        assert_eq!(string.context().len(), 2);
        assert!(string.context().contains(&source));
        assert!(string.context().contains(&output));
    }

    #[test]
    fn string_add_rejects_non_string_rhs() {
        let ir = lower("\"a\" + 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("addition root has binary payload");
        };
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("integer rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "string",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn string_add_evaluates_rhs_before_type_checking_it() {
        let ir = lower("\"a\" + (1 / 0)");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("addition root has binary payload");
        };
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("rhs evaluation error wins");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn numeric_add_rejects_string_rhs_as_non_numeric() {
        let ir = lower("1 + \"a\"");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("addition root has binary payload");
        };
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&ir).expect_err("string rhs is invalid for numeric add");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::String,
            }
        );
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn non_owning_eval_rejects_string_add_heap_values() {
        let ir = lower("\"a\" + \"b\"");
        let error = eval_whnf(&ir).expect_err("string add value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: ValueTag::String,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn non_owning_eval_rejects_heap_values() {
        let ir = lower("\"hello\"");
        let error = eval_whnf(&ir).expect_err("string value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: ir.root,
                tag: ValueTag::String,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );

        let list_ir = lower("[]");
        let error = eval_whnf(&list_ir).expect_err("list value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: list_ir.root,
                tag: ValueTag::List,
            }
        );
        assert_eq!(
            error.span(),
            list_ir.arena.node(list_ir.root).expect("root exists").span
        );

        let non_empty_list_ir = lower("[ 1 ]");
        let error = eval_whnf(&non_empty_list_ir).expect_err("non-empty list needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: non_empty_list_ir.root,
                tag: ValueTag::List,
            }
        );
        assert_eq!(
            error.span(),
            non_empty_list_ir
                .arena
                .node(non_empty_list_ir.root)
                .expect("root exists")
                .span
        );

        let attrs_ir = lower("{}");
        let error = eval_whnf(&attrs_ir).expect_err("attrset value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: attrs_ir.root,
                tag: ValueTag::Attrs,
            }
        );
        assert_eq!(
            error.span(),
            attrs_ir
                .arena
                .node(attrs_ir.root)
                .expect("root exists")
                .span
        );

        let lambda_ir = lower("x: x");
        let error = eval_whnf(&lambda_ir).expect_err("lambda value needs owning heap");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::HeapValueRequiresOwner {
                id: lambda_ir.root,
                tag: ValueTag::Lambda,
            }
        );
        assert_eq!(
            error.span(),
            lambda_ir
                .arena
                .node(lambda_ir.root)
                .expect("root exists")
                .span
        );
    }

    #[test]
    fn unsupported_nodes_report_kind_and_span() {
        let ir = lower("<nixpkgs>");
        let error = eval_whnf(&ir).expect_err("search paths are not implemented yet");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedNode {
                id: ir.root,
                kind: IrKind::SearchPath,
            }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn unsupported_operators_report_operator_and_span() {
        let lhs = IrId::new(0);
        let rhs = IrId::new(1);
        let root = IrId::new(2);
        let span = Span::new(0, 6);
        let binary = manual_ir(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(IrKind::Int, Span::new(5, 6), IrData::Int(2)),
                pure_node(
                    IrKind::BinOp,
                    span,
                    IrData::Binary {
                        op: BinOpKind::PipeRight,
                        lhs,
                        rhs,
                    },
                ),
            ],
        );
        let binary_error = eval_whnf(&binary).expect_err("pipe operator is not implemented yet");
        assert_eq!(
            binary_error.kind(),
            TreeWalkErrorKind::UnsupportedBinaryOp {
                id: root,
                op: BinOpKind::PipeRight,
            }
        );
        assert_eq!(binary_error.span(), span);
    }

    #[test]
    fn invalid_node_ids_are_reported() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let missing = IrId::new(99);
        let error = evaluator
            .eval_node(missing)
            .expect_err("missing node is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidNodeId { id: missing }
        );
        assert_eq!(error.span(), Span::default());
    }

    #[test]
    fn malformed_literal_payloads_are_reported() {
        let cases = [
            (IrKind::Int, IrData::None, "integer payload"),
            (IrKind::Float, IrData::None, "float payload"),
            (IrKind::Bool, IrData::None, "boolean payload"),
            (IrKind::Null, IrData::Bool(false), "empty payload"),
            (IrKind::Str, IrData::None, "string symbol payload"),
            (IrKind::List, IrData::None, "list children"),
            (IrKind::AttrSet, IrData::None, "attrset payload"),
        ];

        for (index, (kind, data, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(index as u32, index as u32 + 1);
            let arena = IrArena::from_raw_parts(
                vec![IrNode::new(kind, span, EffectClass::Pure, data)],
                Vec::new(),
            );
            let ir = empty_ir(root, arena);
            let error = eval_whnf(&ir).expect_err("malformed literal is invalid");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::InvalidPayload {
                    id: root,
                    kind,
                    expected,
                }
            );
            assert_eq!(error.span(), span);
        }
    }

    #[test]
    fn malformed_variable_and_let_payloads_are_reported() {
        let cases = [
            (IrKind::LocalVar, "local payload"),
            (IrKind::UpvalVar, "upvalue payload"),
            (IrKind::Let, "let payload"),
            (IrKind::With, "with pair"),
            (IrKind::WithVar, "with-var payload"),
        ];

        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(10 + index as u32, 11 + index as u32);
            let ir = manual_ir(root, vec![pure_node(kind, span, IrData::None)]);
            let error = eval_whnf(&ir).expect_err("malformed variable or let is invalid");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::InvalidPayload {
                    id: root,
                    kind,
                    expected,
                }
            );
            assert_eq!(error.span(), span);
        }
    }

    #[test]
    fn malformed_function_payloads_are_reported() {
        let cases = [
            (IrKind::Lambda, "lambda payload"),
            (IrKind::Apply, "application pair"),
        ];

        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(20 + index as u32, 21 + index as u32);
            let ir = manual_ir(root, vec![pure_node(kind, span, IrData::None)]);
            let error = eval_whnf(&ir).expect_err("malformed function node is invalid");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::InvalidPayload {
                    id: root,
                    kind,
                    expected,
                }
            );
            assert_eq!(error.span(), span);
        }
    }

    #[test]
    fn invalid_with_chain_metadata_is_reported() {
        let mut symbols = SymbolTable::new();
        let missing = symbols.intern(b"missing").expect("symbol interns");
        let root = IrId::new(0);
        let span = Span::new(0, 7);
        let invalid_chain = manual_ir_with_with_chains(
            root,
            vec![pure_node(
                IrKind::WithVar,
                span,
                IrData::WithVar {
                    symbol: missing,
                    chain: 0,
                },
            )],
            symbols.clone(),
            Vec::new(),
        );
        let error = eval_whnf(&invalid_chain).expect_err("missing with chain is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidWithChain { id: root, chain: 0 }
        );
        assert_eq!(error.span(), span);

        let scope = IrId::new(1);
        let missing_scope = manual_ir_with_with_chains(
            root,
            vec![
                pure_node(
                    IrKind::WithVar,
                    span,
                    IrData::WithVar {
                        symbol: missing,
                        chain: 0,
                    },
                ),
                pure_node(IrKind::AttrSet, Span::new(10, 12), IrData::None),
            ],
            symbols,
            vec![IrWithChain::new(vec![scope].into_boxed_slice())],
        );
        let error = eval_whnf(&missing_scope).expect_err("inactive with scope is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::MissingWithScope { id: root, scope }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_environment_accesses_are_reported() {
        let root = IrId::new(0);
        let span = Span::new(0, 1);
        let local_ir = manual_ir(
            root,
            vec![pure_node(IrKind::LocalVar, span, IrData::Local { slot: 0 })],
        );
        let local_error = eval_whnf(&local_ir).expect_err("local needs an environment");

        assert_eq!(
            local_error.kind(),
            TreeWalkErrorKind::MissingEnvironment { id: root }
        );
        assert_eq!(local_error.span(), span);

        let upval_ir = manual_ir(
            root,
            vec![pure_node(
                IrKind::UpvalVar,
                span,
                IrData::Upval { depth: 0, slot: 0 },
            )],
        );
        let upval_error = eval_whnf(&upval_ir).expect_err("upvalue needs an environment");

        assert_eq!(
            upval_error.kind(),
            TreeWalkErrorKind::InvalidUpvalueDepth {
                id: root,
                depth: 0,
                frames: 0,
            }
        );
        assert_eq!(upval_error.span(), span);
    }

    #[test]
    fn invalid_let_frame_metadata_is_reported() {
        let root = IrId::new(0);
        let body = IrId::new(1);
        let span = Span::new(0, 10);
        let missing_frame = manual_ir(
            root,
            vec![
                pure_node(
                    IrKind::Let,
                    span,
                    IrData::Let {
                        bindings: IrBindingSlice::new(0, 0),
                        body,
                        frame: None,
                    },
                ),
                pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
            ],
        );
        let missing_error = eval_whnf(&missing_frame).expect_err("let frame metadata must exist");

        assert_eq!(
            missing_error.kind(),
            TreeWalkErrorKind::MissingFrameMetadata { id: root }
        );
        assert_eq!(missing_error.span(), span);

        let frame = FrameId::new(0);
        let invalid_frame = manual_ir(
            root,
            vec![
                pure_node(
                    IrKind::Let,
                    span,
                    IrData::Let {
                        bindings: IrBindingSlice::new(0, 0),
                        body,
                        frame: Some(frame),
                    },
                ),
                pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
            ],
        );
        let invalid_error = eval_whnf(&invalid_frame).expect_err("frame id must resolve");

        assert_eq!(
            invalid_error.kind(),
            TreeWalkErrorKind::InvalidFrameId {
                id: root,
                frame: frame.as_u32(),
            }
        );
        assert_eq!(invalid_error.span(), span);
    }

    #[test]
    fn invalid_string_symbols_are_reported() {
        let root = IrId::new(0);
        let symbol = Symbol::new(99);
        let span = Span::new(3, 8);
        let ir = manual_ir(
            root,
            vec![pure_node(IrKind::Str, span, IrData::Symbol(symbol))],
        );
        let error = eval_whnf_owned(&ir).expect_err("string symbol must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_list_child_slices_are_reported() {
        let root = IrId::new(0);
        let slice = IrChildSlice::new(7, 1);
        let span = Span::new(0, 2);
        let ir = manual_ir(
            root,
            vec![pure_node(IrKind::List, span, IrData::Children(slice))],
        );
        let error = eval_whnf_owned(&ir).expect_err("list child slice must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidChildSlice { id: root, slice }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_has_attr_paths_are_reported() {
        let receiver = IrId::new(0);
        let root = IrId::new(1);
        let path = IrAttrPathId::new(2);
        let span = Span::new(0, 5);
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let ir = manual_ir_with_attr_paths(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(
                    IrKind::HasAttr,
                    span,
                    IrData::HasAttr {
                        site: IrInlineCacheSiteId::new(0),
                        receiver,
                        path,
                    },
                ),
            ],
            symbols,
            vec![Box::new([IrAttrPathSegment::Static(a)]), Box::new([])],
        );
        let error = eval_whnf_owned(&ir).expect_err("attr-path id must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidAttrPath { id: root, path }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_select_paths_are_reported() {
        let receiver = IrId::new(0);
        let root = IrId::new(1);
        let path = IrAttrPathId::new(2);
        let span = Span::new(0, 5);
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let ir = manual_ir_with_attr_paths(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(
                    IrKind::Select,
                    span,
                    IrData::Select {
                        site: IrInlineCacheSiteId::new(0),
                        receiver,
                        path,
                        default: None,
                    },
                ),
            ],
            symbols,
            vec![Box::new([IrAttrPathSegment::Static(a)]), Box::new([])],
        );
        let error = eval_whnf_owned(&ir).expect_err("attr-path id must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidAttrPath { id: root, path }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_has_attr_static_symbols_are_reported() {
        let receiver = IrId::new(0);
        let root = IrId::new(1);
        let path = IrAttrPathId::new(0);
        let span = Span::new(0, 5);
        let symbol = Symbol::new(99);
        let ir = manual_ir_with_attr_paths(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(
                    IrKind::HasAttr,
                    span,
                    IrData::HasAttr {
                        site: IrInlineCacheSiteId::new(0),
                        receiver,
                        path,
                    },
                ),
            ],
            SymbolTable::new(),
            vec![Box::new([IrAttrPathSegment::Static(symbol)])],
        );
        let error = eval_whnf_owned(&ir).expect_err("static path symbol must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_select_static_symbols_are_reported() {
        let receiver = IrId::new(0);
        let root = IrId::new(1);
        let path = IrAttrPathId::new(0);
        let span = Span::new(0, 5);
        let symbol = Symbol::new(99);
        let ir = manual_ir_with_attr_paths(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(0, 1), IrData::Int(1)),
                pure_node(
                    IrKind::Select,
                    span,
                    IrData::Select {
                        site: IrInlineCacheSiteId::new(0),
                        receiver,
                        path,
                        default: None,
                    },
                ),
            ],
            SymbolTable::new(),
            vec![Box::new([IrAttrPathSegment::Static(symbol)])],
        );
        let error = eval_whnf_owned(&ir).expect_err("static path symbol must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidSymbol { id: root, symbol }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_attrset_binding_slices_are_reported() {
        let root = IrId::new(0);
        let slice = IrBindingSlice::new(7, 1);
        let span = Span::new(0, 2);
        let ir = manual_ir(
            root,
            vec![pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: slice,
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            )],
        );
        let error = eval_whnf_owned(&ir).expect_err("attrset binding slice must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidBindingSlice { id: root, slice }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_attrset_shape_ids_are_reported() {
        let root = IrId::new(0);
        let shape = IrShapeId::new(0);
        let span = Span::new(0, 2);
        let ir = manual_ir(
            root,
            vec![pure_node(
                IrKind::AttrSet,
                span,
                IrData::AttrSet {
                    shape,
                    bindings: IrBindingSlice::new(0, 0),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            )],
        );
        let error = eval_whnf_owned(&ir).expect_err("attrset shape must exist");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidShapeId { id: root, shape }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn invalid_recursive_attrset_frame_metadata_is_reported() {
        fn recursive_attrset_ir(frame: Option<FrameId>, frames: Vec<FrameInfo>) -> Ir {
            let mut symbols = SymbolTable::new();
            let a = symbols.intern(b"a").expect("symbol interns");
            let value = IrId::new(0);
            let root = IrId::new(1);
            let mut ir = manual_ir_with_attr_tables(
                root,
                vec![
                    pure_node(IrKind::Int, Span::new(8, 9), IrData::Int(1)),
                    pure_node(
                        IrKind::AttrSet,
                        Span::new(0, 10),
                        IrData::AttrSet {
                            shape: IrShapeId::new(0),
                            bindings: IrBindingSlice::new(0, 1),
                            recursive: true,
                            has_dynamic: false,
                            frame,
                        },
                    ),
                ],
                symbols,
                vec![IrBinding {
                    key: IrAttrPathSegment::Static(a),
                    value,
                }],
                vec![IrShape::new(vec![a].into_boxed_slice())],
            );
            ir.frames = frames.into_boxed_slice();
            ir
        }

        let missing_frame = recursive_attrset_ir(None, Vec::new());
        let missing_error =
            eval_whnf_owned(&missing_frame).expect_err("recursive attrset frame must exist");

        assert_eq!(
            missing_error.kind(),
            TreeWalkErrorKind::MissingFrameMetadata { id: IrId::new(1) }
        );
        assert_eq!(missing_error.span(), Span::new(0, 10));

        let frame = FrameId::new(0);
        let invalid_frame = recursive_attrset_ir(Some(frame), Vec::new());
        let invalid_error = eval_whnf_owned(&invalid_frame).expect_err("frame id must resolve");

        assert_eq!(
            invalid_error.kind(),
            TreeWalkErrorKind::InvalidFrameId {
                id: IrId::new(1),
                frame: frame.as_u32(),
            }
        );
        assert_eq!(invalid_error.span(), Span::new(0, 10));

        let mismatch = recursive_attrset_ir(
            Some(frame),
            vec![FrameInfo {
                slot_count: 2,
                captures: Vec::new().into_boxed_slice(),
                rec: true,
                has_with: false,
            }],
        );
        let mismatch_error =
            eval_whnf_owned(&mismatch).expect_err("frame slots must match bindings");

        assert_eq!(
            mismatch_error.kind(),
            TreeWalkErrorKind::AttrSetFrameSlotMismatch {
                id: IrId::new(1),
                frame_slots: 2,
                bindings: 1,
            }
        );
        assert_eq!(mismatch_error.span(), Span::new(0, 10));
    }

    #[test]
    fn attrset_shape_length_mismatches_are_reported() {
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let value = IrId::new(0);
        let root = IrId::new(1);
        let shape = IrShapeId::new(0);
        let span = Span::new(0, 8);
        let ir = manual_ir_with_attr_tables(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
                pure_node(
                    IrKind::AttrSet,
                    span,
                    IrData::AttrSet {
                        shape,
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: false,
                        frame: None,
                    },
                ),
            ],
            symbols,
            vec![IrBinding {
                key: IrAttrPathSegment::Static(a),
                value,
            }],
            vec![IrShape::new(Vec::new().into_boxed_slice())],
        );
        let error = eval_whnf_owned(&ir).expect_err("attrset shape length must match bindings");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::AttrSetShapeLengthMismatch {
                id: root,
                shape,
                shape_keys: 0,
                binding_keys: 1,
            }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn attrset_shape_key_mismatches_are_reported() {
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("a symbol interns");
        let b = symbols.intern(b"b").expect("b symbol interns");
        let value = IrId::new(0);
        let root = IrId::new(1);
        let shape = IrShapeId::new(0);
        let span = Span::new(0, 8);
        let ir = manual_ir_with_attr_tables(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(6, 7), IrData::Int(1)),
                pure_node(
                    IrKind::AttrSet,
                    span,
                    IrData::AttrSet {
                        shape,
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: false,
                        frame: None,
                    },
                ),
            ],
            symbols,
            vec![IrBinding {
                key: IrAttrPathSegment::Static(a),
                value,
            }],
            vec![IrShape::new(vec![b].into_boxed_slice())],
        );
        let error = eval_whnf_owned(&ir).expect_err("attrset shape keys must match bindings");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::AttrSetShapeKeyMismatch {
                id: root,
                shape,
                index: 0,
                expected: b,
                actual: a,
            }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn dynamic_attrset_bindings_evaluate_even_with_false_dynamic_flag() {
        let key = IrId::new(0);
        let value = IrId::new(1);
        let root = IrId::new(2);
        let shape = IrShapeId::new(0);
        let span = Span::new(0, 12);
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("symbol interns");
        let ir = manual_ir_with_attr_tables(
            root,
            vec![
                pure_node(IrKind::Str, Span::new(3, 8), IrData::Symbol(a)),
                pure_node(IrKind::Int, Span::new(9, 10), IrData::Int(1)),
                pure_node(
                    IrKind::AttrSet,
                    span,
                    IrData::AttrSet {
                        shape,
                        bindings: IrBindingSlice::new(0, 1),
                        recursive: false,
                        has_dynamic: false,
                        frame: None,
                    },
                ),
            ],
            symbols,
            vec![IrBinding {
                key: IrAttrPathSegment::Dynamic(key),
                value,
            }],
            vec![IrShape::new(Vec::new().into_boxed_slice())],
        );
        let outcome = eval_whnf_owned(&ir).expect("dynamic key evaluates");
        let attrs = outcome
            .heap()
            .get_attrs(outcome.value())
            .expect("attrset is heap-owned");

        assert_eq!(attrs.get(a).expect("dynamic key exists").as_int(), Ok(1));
    }

    #[test]
    fn malformed_thunk_payloads_are_reported_through_list_children() {
        let root = IrId::new(0);
        let child = IrId::new(1);
        let root_span = Span::new(0, 7);
        let child_span = Span::new(2, 5);
        let ir = empty_ir(
            root,
            IrArena::from_raw_parts(
                vec![
                    pure_node(
                        IrKind::List,
                        root_span,
                        IrData::Children(IrChildSlice::new(0, 1)),
                    ),
                    pure_node(IrKind::ThunkAlloc, child_span, IrData::None),
                ],
                vec![child],
            ),
        );

        let error = eval_whnf_owned(&ir).expect_err("malformed thunk child is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: child,
                kind: IrKind::ThunkAlloc,
                expected: "thunk body",
            }
        );
        assert_eq!(error.span(), child_span);
    }

    #[test]
    fn malformed_thunk_body_ids_are_reported_through_list_children() {
        let root = IrId::new(0);
        let child = IrId::new(1);
        let missing = IrId::new(99);
        let root_span = Span::new(0, 7);
        let child_span = Span::new(2, 5);
        let ir = empty_ir(
            root,
            IrArena::from_raw_parts(
                vec![
                    pure_node(
                        IrKind::List,
                        root_span,
                        IrData::Children(IrChildSlice::new(0, 1)),
                    ),
                    pure_node(IrKind::ThunkAlloc, child_span, IrData::Node(missing)),
                ],
                vec![child],
            ),
        );

        let error = eval_whnf_owned(&ir).expect_err("missing thunk body is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidNodeId { id: missing }
        );
        assert_eq!(error.span(), Span::default());
    }

    #[test]
    fn if_evaluates_only_the_selected_branch() {
        assert_eq!(eval("if true then 1 else 2").as_int(), Ok(1));
        assert_eq!(eval("if false then 1 else 2").as_int(), Ok(2));

        let lazy_else = eval("if true then 7 else (1 ++ 2)");
        assert_eq!(lazy_else.as_int(), Ok(7));

        let lazy_then = eval("if false then (1 ++ 2) else 9");
        assert_eq!(lazy_then.as_int(), Ok(9));
    }

    #[test]
    fn if_condition_must_be_bool() {
        let ir = lower("if 1 then 2 else 3");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Triple { first, .. } = root.data else {
            panic!("if root has triple payload");
        };
        let condition_span = ir.arena.node(first).expect("condition exists").span;

        let error = eval_whnf(&ir).expect_err("integer condition is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: first,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), condition_span);
    }

    #[test]
    fn malformed_if_payloads_are_reported() {
        let root = IrId::new(0);
        let span = Span::new(10, 12);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::If,
                span,
                EffectClass::Pure,
                IrData::None,
            )],
            Vec::new(),
        );
        let ir = empty_ir(root, arena);
        let error = eval_whnf(&ir).expect_err("malformed if is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind: IrKind::If,
                expected: "if payload",
            }
        );
        assert_eq!(error.span(), span);
    }

    #[test]
    fn unary_not_evaluates_boolean_operands() {
        assert_eq!(eval("!true").as_bool(), Ok(false));
        assert_eq!(eval("!false").as_bool(), Ok(true));
    }

    #[test]
    fn unary_not_rejects_non_bool_operands() {
        let ir = lower("!1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Unary { operand, .. } = root.data else {
            panic!("not root has unary payload");
        };
        let operand_span = ir.arena.node(operand).expect("operand exists").span;

        let error = eval_whnf(&ir).expect_err("integer operand is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: operand,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), operand_span);
    }

    #[test]
    fn numeric_unary_negation_handles_ints_and_floats() {
        assert_eq!(eval("-1").as_int(), Ok(-1));
        assert_eq!(eval("-1.5").as_float(), Ok(-1.5));

        let operand = IrId::new(0);
        let root = IrId::new(1);
        let root_span = Span::new(0, 2);
        let ir = manual_ir(
            root,
            vec![
                pure_node(IrKind::Int, Span::new(1, 2), IrData::Int(i64::MIN)),
                pure_node(
                    IrKind::UnaryOp,
                    root_span,
                    IrData::Unary {
                        op: UnaryOpKind::Neg,
                        operand,
                    },
                ),
            ],
        );

        let error = eval_whnf(&ir).expect_err("negating i64::MIN overflows");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ArithmeticOverflow {
                id: root,
                op: ArithmeticOp::Neg,
            }
        );
        assert_eq!(error.span(), root_span);
    }

    #[test]
    fn numeric_unary_negation_rejects_non_numbers() {
        let ir = lower("-true");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Unary { operand, .. } = root.data else {
            panic!("negation root has unary payload");
        };
        let operand_span = ir.arena.node(operand).expect("operand exists").span;

        let error = eval_whnf(&ir).expect_err("boolean negation operand is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: operand,
                expected: "number",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), operand_span);
    }

    #[test]
    fn numeric_arithmetic_handles_ints_and_float_promotion() {
        assert_eq!(eval("1 + 2").as_int(), Ok(3));
        assert_eq!(eval("5 - 8").as_int(), Ok(-3));
        assert_eq!(eval("2 * 3").as_int(), Ok(6));
        assert_eq!(eval("1 + 2.5").as_float(), Ok(3.5));
        assert_eq!(eval("2 * 0.5").as_float(), Ok(1.0));
    }

    #[test]
    fn integer_division_truncates_toward_zero() {
        assert_eq!(eval("7 / (-2)").as_int(), Ok(-3));
    }

    #[test]
    fn float_or_mixed_division_returns_float() {
        assert_eq!(eval("7 / 2.0").as_float(), Ok(3.5));
        assert_eq!(eval("7.0 / 2").as_float(), Ok(3.5));
    }

    #[test]
    fn division_by_zero_errors_at_operator_span() {
        let ir = lower("1 / 0");
        let error = eval_whnf(&ir).expect_err("integer division by zero is invalid");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: ir.root }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );

        let float_ir = lower("1.0 / -0.0");
        let error = eval_whnf(&float_ir).expect_err("float division by zero is invalid");
        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: float_ir.root }
        );
        assert_eq!(
            error.span(),
            float_ir
                .arena
                .node(float_ir.root)
                .expect("root exists")
                .span
        );
    }

    #[test]
    fn integer_add_sub_mul_wrap_on_overflow() {
        let cases = [
            (BinOpKind::Add, i64::MAX, 1, i64::MIN),
            (BinOpKind::Sub, i64::MIN, 1, i64::MAX),
            (BinOpKind::Mul, i64::MAX, 2, -2),
        ];

        for (op, left, right, expected) in cases {
            let value = eval_whnf(&int_binary_ir(op, left, right)).expect("arithmetic evaluates");

            assert_eq!(value.as_int(), Ok(expected));
        }
    }

    #[test]
    fn integer_division_overflow_errors_at_operator_span() {
        let ir = int_binary_ir(BinOpKind::Div, i64::MIN, -1);
        let root_span = ir.arena.node(ir.root).expect("root exists").span;
        let error = eval_whnf(&ir).expect_err("integer division overflows");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::ArithmeticOverflow {
                id: ir.root,
                op: ArithmeticOp::Div,
            }
        );
        assert_eq!(error.span(), root_span);
    }

    #[test]
    fn numeric_operators_force_rhs_before_type_checks() {
        let rhs_ir = lower("1 + true");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("addition root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&rhs_ir).expect_err("boolean rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let lhs_ir = lower("true - (1 / 0)");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("subtraction root has binary payload");
        };
        let rhs_span = lhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&lhs_ir).expect_err("rhs evaluation error wins before lhs type");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let lhs_type_ir = lower("true - false");
        let root = lhs_type_ir
            .arena
            .node(lhs_type_ir.root)
            .expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("subtraction root has binary payload");
        };
        let lhs_span = lhs_type_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&lhs_type_ir).expect_err("boolean lhs is invalid after rhs force");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "number",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), lhs_span);
    }

    #[test]
    fn scalar_equality_handles_inline_values() {
        assert_eq!(eval("1 == 1").as_bool(), Ok(true));
        assert_eq!(eval("1 == 2").as_bool(), Ok(false));
        assert_eq!(eval("1 == 1.0").as_bool(), Ok(true));
        assert_eq!(eval("1 != 1.5").as_bool(), Ok(true));
        assert_eq!(eval("true == true").as_bool(), Ok(true));
        assert_eq!(eval("true != false").as_bool(), Ok(true));
        assert_eq!(eval("null == null").as_bool(), Ok(true));
        assert_eq!(eval("null == false").as_bool(), Ok(false));
        assert_eq!(eval("1 == true").as_bool(), Ok(false));
    }

    #[test]
    fn string_equality_compares_bytes() {
        assert_eq!(eval("\"a\" == \"a\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\" == \"b\"").as_bool(), Ok(false));
        assert_eq!(eval("\"a\" != \"b\"").as_bool(), Ok(true));
        assert_eq!(eval("\"line\\n\" == \"line\\n\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\" == 1").as_bool(), Ok(false));
        assert_eq!(eval("1 != \"a\"").as_bool(), Ok(true));
    }

    #[test]
    fn string_equality_ignores_contexts() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = *ir.arena.node(ir.root).expect("root exists");
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let output =
            ContextElement::single_output(b"/nix/store/derivation.drv".to_vec(), b"out".to_vec())
                .expect("output context is valid");
        let left = evaluator
            .heap
            .alloc_string(NixString::new(
                b"same".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("left string allocates");
        let right = evaluator
            .heap
            .alloc_string(NixString::new(
                b"same".to_vec(),
                StringContext::singleton(output).expect("output context allocates"),
            ))
            .expect("right string allocates");

        assert_eq!(
            evaluator
                .values_equal(ir.root, &node, left, right, EqualityContext::Direct)
                .expect("strings compare"),
            true
        );
    }

    #[test]
    fn list_equality_is_structural_and_short_circuits() {
        assert_eq!(eval("[1 \"a\" null] == [1 \"a\" null]").as_bool(), Ok(true));
        assert_eq!(eval("[1] != [1 2]").as_bool(), Ok(true));
        assert_eq!(eval("[1 2] == [1 3]").as_bool(), Ok(false));
        assert_eq!(eval("[1 (1 / 0)] == [2 (1 / 0)]").as_bool(), Ok(false));
        assert_eq!(eval("let f = x: x; in [ f ] == [ f ]").as_bool(), Ok(true));
        assert_eq!(eval("[ (x: x) ] == [ (x: x) ]").as_bool(), Ok(false));
        assert_eq!(
            eval("let v = { a = x: x; }; in [ v.a ] == [ v.a ]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let v = { a = x: x; }; xs = [ v.a ]; in xs == xs").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let xs = [ (1 / 0) ]; in [ xs ] == [ xs ]").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let nan = ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)); in [ nan ] == [ nan ]")
                .as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval(
                "[ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ] == [ ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308)) ]"
            )
            .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn attrset_equality_is_structural_and_short_circuits() {
        assert_eq!(
            eval("{ b = 2; a = 1; } == { a = 1; b = 2; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("{ a = 1; } == { a = 1; b = 1 / 0; }").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("{ a = 1; z = 1 / 0; } == { a = 2; z = 1 / 0; }").as_bool(),
            Ok(false)
        );
        let z_first = lower("{ z = 1 / 0; a = 1; } == { a = 2; z = 1 / 0; }");
        let z_error = eval_whnf(&z_first).expect_err("symbol-order comparison forces z first");
        let TreeWalkErrorKind::DivisionByZero { .. } = z_error.kind() else {
            panic!("expected division by zero from z value");
        };
        assert_eq!(
            eval("{ a = { x = 1; }; } == { a = { x = 1; }; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let f = x: x; in { inherit f; } == { inherit f; }").as_bool(),
            Ok(true)
        );
        assert_eq!(
            eval("let s = { a = 1 / 0; }; in [ s ] == [ s ]").as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn direct_function_equality_is_always_false() {
        assert_eq!(eval("let f = x: x; in f == f").as_bool(), Ok(false));
        assert_eq!(eval("let f = x: x; in f != f").as_bool(), Ok(true));
        assert_eq!(
            eval("let f = x: x; g = x: x; in f == g").as_bool(),
            Ok(false)
        );
        assert_eq!(eval("(x: x) == 1").as_bool(), Ok(false));

        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = ir.arena.node(ir.root).expect("root exists");
        let ptr = NonNull::<HeapObject>::dangling();
        let lambda = Value::lambda(ptr).expect("aligned lambda pointer");
        let primop = Value::primop(ptr).expect("aligned primop pointer");
        assert_eq!(
            evaluator.values_equal(ir.root, node, primop, primop, EqualityContext::Direct),
            Ok(false)
        );
        assert_eq!(
            evaluator.values_equal(ir.root, node, lambda, primop, EqualityContext::Direct),
            Ok(false)
        );
    }

    #[test]
    fn scalar_equality_evaluates_operands_left_to_right() {
        let rhs_ir = lower("false == (1 / 0)");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("equality root has binary payload");
        };
        let rhs_id = rhs;
        let rhs_span = rhs_ir.arena.node(rhs_id).expect("rhs exists").span;
        let error = eval_whnf(&rhs_ir).expect_err("rhs division by zero is evaluated");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: rhs_id }
        );
        assert_eq!(error.span(), rhs_span);

        let lhs_ir = lower("(1 / 0) == false");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("equality root has binary payload");
        };
        let lhs_id = lhs;
        let lhs_span = lhs_ir.arena.node(lhs_id).expect("lhs exists").span;
        let error = eval_whnf(&lhs_ir).expect_err("lhs division by zero is evaluated first");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { id: lhs_id }
        );
        assert_eq!(error.span(), lhs_span);
    }

    #[test]
    fn raw_thunk_equality_is_unsupported() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = ir.arena.node(ir.root).expect("root exists");
        let ptr = NonNull::<HeapObject>::dangling();
        let left = Value::thunk(ptr).expect("aligned thunk pointer");
        let right = Value::thunk(ptr).expect("aligned thunk pointer");

        let error = evaluator
            .values_equal(ir.root, node, left, right, EqualityContext::Direct)
            .expect_err("raw thunk equality is not supported");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedEqualityType {
                id: ir.root,
                left: ValueTag::Thunk,
                right: ValueTag::Thunk,
            }
        );
        assert_eq!(error.span(), node.span);
    }

    #[test]
    fn numeric_comparisons_handle_ints_floats_and_promotion() {
        assert_eq!(eval("1 < 2").as_bool(), Ok(true));
        assert_eq!(eval("2 > 1").as_bool(), Ok(true));
        assert_eq!(eval("2 <= 2").as_bool(), Ok(true));
        assert_eq!(eval("2 >= 3").as_bool(), Ok(false));
        assert_eq!(eval("1 < 1.5").as_bool(), Ok(true));
        assert_eq!(eval("1.5 >= 2").as_bool(), Ok(false));
    }

    #[test]
    fn string_comparisons_use_byte_order() {
        assert_eq!(eval("\"a\" < \"b\"").as_bool(), Ok(true));
        assert_eq!(eval("\"b\" > \"a\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\" <= \"a\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\" >= \"b\"").as_bool(), Ok(false));
        assert_eq!(eval("\"Z\" < \"a\"").as_bool(), Ok(true));
        assert_eq!(eval("\"a\\n\" < \"aa\"").as_bool(), Ok(true));
    }

    #[test]
    fn string_comparisons_use_bytes_not_contexts() {
        let ir = lower("1");
        let mut evaluator = TreeWalk::new(&ir);
        let node = *ir.arena.node(ir.root).expect("root exists");
        let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
            .expect("source context is valid");
        let output =
            ContextElement::single_output(b"/nix/store/derivation.drv".to_vec(), b"out".to_vec())
                .expect("output context is valid");
        let left = evaluator
            .heap
            .alloc_string(NixString::new(
                b"same".to_vec(),
                StringContext::singleton(source).expect("source context allocates"),
            ))
            .expect("left string allocates");
        let right = evaluator
            .heap
            .alloc_string(NixString::new(
                b"same".to_vec(),
                StringContext::singleton(output).expect("output context allocates"),
            ))
            .expect("right string allocates");

        assert_eq!(
            evaluator
                .compare_strings(ir.root, &node, ComparisonOp::Le, left, right)
                .expect("strings compare")
                .as_bool(),
            Ok(true)
        );
        assert_eq!(
            evaluator
                .compare_strings(ir.root, &node, ComparisonOp::Ge, left, right)
                .expect("strings compare")
                .as_bool(),
            Ok(true)
        );
        assert_eq!(
            evaluator
                .compare_strings(ir.root, &node, ComparisonOp::Lt, left, right)
                .expect("strings compare")
                .as_bool(),
            Ok(false)
        );
    }

    #[test]
    fn list_comparisons_are_lexicographic() {
        assert_eq!(eval("[1 2] < [1 3]").as_bool(), Ok(true));
        assert_eq!(eval("[1 3] > [1 2]").as_bool(), Ok(true));
        assert_eq!(eval("[1 2] <= [1 2]").as_bool(), Ok(true));
        assert_eq!(eval("[1 2] >= [1 3]").as_bool(), Ok(false));
        assert_eq!(eval("[1] < [1 0]").as_bool(), Ok(true));
        assert_eq!(eval("[1 0] > [1]").as_bool(), Ok(true));
        assert_eq!(eval("[] < [0]").as_bool(), Ok(true));
        assert_eq!(eval("[1 \"a\"] < [1 \"b\"]").as_bool(), Ok(true));
        assert_eq!(eval("[[1 2]] < [[1 3]]").as_bool(), Ok(true));
    }

    #[test]
    fn list_comparisons_short_circuit() {
        assert_eq!(eval("[1 (1 / 0)] < [2 (1 / 0)]").as_bool(), Ok(true));
        assert_eq!(eval("[2 (1 / 0)] < [1 (1 / 0)]").as_bool(), Ok(false));

        let ir = lower("[1 (1 / 0)] <= [1 (2 / 0)]");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let left = ir.arena.node(lhs).expect("lhs exists");
        let IrData::Children(left_elements) = left.data else {
            panic!("lhs list has children");
        };
        let left_elements = ir
            .arena
            .child_slice(left_elements)
            .expect("lhs elements exist");
        let throwing_thunk = ir.arena.node(left_elements[1]).expect("thunk exists");
        let IrData::Node(throwing_element) = throwing_thunk.data else {
            panic!("list element is a thunk");
        };
        let throwing_span = ir
            .arena
            .node(throwing_element)
            .expect("throwing element exists")
            .span;

        let error = eval_whnf(&ir).expect_err("equal prefix forces next element");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero {
                id: throwing_element
            }
        );
        assert_eq!(error.span(), throwing_span);
    }

    #[test]
    fn list_comparisons_handle_recursive_container_equality() {
        assert_eq!(eval("let xs = [ xs ]; in xs < xs").as_bool(), Ok(false));
        assert_eq!(eval("let xs = [ xs ]; in xs <= xs").as_bool(), Ok(true));
        assert_eq!(
            eval("let s = rec { a = s; }; in [s] < [s]").as_bool(),
            Ok(false)
        );
        assert_eq!(
            eval("let s = rec { a = s; }; in [s] <= [s]").as_bool(),
            Ok(true)
        );
    }

    #[test]
    fn structural_equality_still_forces_shared_list_elements() {
        let error = eval_whnf(&lower("let xs = [ (1 / 0) ]; in xs == xs"))
            .expect_err("shared throwing list element is forced");

        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::DivisionByZero { .. }
        ));
    }

    #[test]
    fn list_comparisons_type_check_operands_left_to_right() {
        let rhs_ir = lower("[1] < true");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&rhs_ir).expect_err("boolean rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "list",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let nested_ir = lower("[1] < [\"a\"]");
        let error = eval_whnf_owned(&nested_ir).expect_err("string element is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: nested_ir.root,
                expected: "number",
                actual: ValueTag::String,
            }
        );
        assert_eq!(
            error.span(),
            nested_ir
                .arena
                .node(nested_ir.root)
                .expect("root exists")
                .span
        );

        let lhs_ir = lower("false < [(1 / 0)]");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { lhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let lhs_span = lhs_ir.arena.node(lhs).expect("lhs exists").span;

        let error = eval_whnf(&lhs_ir).expect_err("boolean lhs is invalid before rhs");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: lhs,
                expected: "number, string, or list",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), lhs_span);
    }

    #[test]
    fn comparisons_force_operands_before_type_checks() {
        let rhs_ir = lower("1 < true");
        let root = rhs_ir.arena.node(rhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&rhs_ir).expect_err("boolean rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let string_rhs_ir = lower("1 < \"a\"");
        let root = string_rhs_ir
            .arena
            .node(string_rhs_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = string_rhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&string_rhs_ir).expect_err("string rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "number",
                actual: ValueTag::String,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let string_left_ir = lower("\"a\" < true");
        let root = string_left_ir
            .arena
            .node(string_left_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = string_left_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&string_left_ir).expect_err("boolean rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "string",
                actual: ValueTag::Bool,
            }
        );
        assert_eq!(error.span(), rhs_span);

        let rhs_error_ir = lower("\"a\" < (1 / 0)");
        let root = rhs_error_ir
            .arena
            .node(rhs_error_ir.root)
            .expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = rhs_error_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf_owned(&rhs_error_ir).expect_err("rhs evaluation error wins");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);

        let lhs_ir = lower("false < (1 / 0)");
        let root = lhs_ir.arena.node(lhs_ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("comparison root has binary payload");
        };
        let rhs_span = lhs_ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&lhs_ir).expect_err("rhs evaluation error wins before lhs type");

        assert_eq!(error.kind(), TreeWalkErrorKind::DivisionByZero { id: rhs });
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn boolean_binary_operators_short_circuit() {
        assert_eq!(eval("true && true").as_bool(), Ok(true));
        assert_eq!(eval("true && false").as_bool(), Ok(false));
        assert_eq!(eval("false && (1 ++ 2)").as_bool(), Ok(false));

        assert_eq!(eval("true || (1 ++ 2)").as_bool(), Ok(true));
        assert_eq!(eval("false || true").as_bool(), Ok(true));
        assert_eq!(eval("false || false").as_bool(), Ok(false));

        assert_eq!(eval("false -> (1 ++ 2)").as_bool(), Ok(true));
        assert_eq!(eval("true -> true").as_bool(), Ok(true));
        assert_eq!(eval("true -> false").as_bool(), Ok(false));
    }

    #[test]
    fn boolean_binary_operators_type_check_evaluated_rhs() {
        let ir = lower("true && 1");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Binary { rhs, .. } = root.data else {
            panic!("and root has binary payload");
        };
        let rhs_span = ir.arena.node(rhs).expect("rhs exists").span;

        let error = eval_whnf(&ir).expect_err("integer rhs is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: rhs,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), rhs_span);
    }

    #[test]
    fn malformed_operator_payloads_are_reported() {
        let cases = [
            (IrKind::UnaryOp, "unary payload"),
            (IrKind::BinOp, "binary payload"),
        ];

        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(20 + index as u32, 21 + index as u32);
            let arena = IrArena::from_raw_parts(
                vec![IrNode::new(kind, span, EffectClass::Pure, IrData::None)],
                Vec::new(),
            );
            let ir = empty_ir(root, arena);
            let error = eval_whnf(&ir).expect_err("malformed operator is invalid");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::InvalidPayload {
                    id: root,
                    kind,
                    expected,
                }
            );
            assert_eq!(error.span(), span);
        }
    }

    #[test]
    fn malformed_attr_access_payloads_are_reported() {
        let cases = [
            (IrKind::Select, "select payload"),
            (IrKind::HasAttr, "has-attr payload"),
        ];

        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let root = IrId::new(0);
            let span = Span::new(30 + index as u32, 31 + index as u32);
            let arena = IrArena::from_raw_parts(
                vec![IrNode::new(kind, span, EffectClass::Pure, IrData::None)],
                Vec::new(),
            );
            let ir = empty_ir(root, arena);
            let error = eval_whnf(&ir).expect_err("malformed attr access is invalid");

            assert_eq!(
                error.kind(),
                TreeWalkErrorKind::InvalidPayload {
                    id: root,
                    kind,
                    expected,
                }
            );
            assert_eq!(error.span(), span);
        }
    }

    #[test]
    fn assert_evaluates_body_only_when_condition_is_true() {
        assert_eq!(eval("assert true; 5").as_int(), Ok(5));

        let ir = lower("assert false; (1 ++ 2)");
        let lazy_body = eval_whnf(&ir).expect_err("false assertion stops before body");
        assert_eq!(
            lazy_body.kind(),
            TreeWalkErrorKind::AssertionFailed { id: ir.root }
        );
    }

    #[test]
    fn assert_false_reports_assertion_span() {
        let ir = lower("assert false; 1");
        let error = eval_whnf(&ir).expect_err("assertion fails");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::AssertionFailed { id: ir.root }
        );
        assert_eq!(
            error.span(),
            ir.arena.node(ir.root).expect("root exists").span
        );
    }

    #[test]
    fn assert_condition_must_be_bool() {
        let ir = lower("assert 1; 2");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Pair { first, .. } = root.data else {
            panic!("assert root has pair payload");
        };
        let condition_span = ir.arena.node(first).expect("condition exists").span;

        let error = eval_whnf(&ir).expect_err("integer condition is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::Type {
                id: first,
                expected: "bool",
                actual: ValueTag::Int,
            }
        );
        assert_eq!(error.span(), condition_span);
    }

    #[test]
    fn malformed_assert_payloads_are_reported() {
        let root = IrId::new(0);
        let span = Span::new(30, 35);
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Assert,
                span,
                EffectClass::Pure,
                IrData::None,
            )],
            Vec::new(),
        );
        let ir = empty_ir(root, arena);
        let error = eval_whnf(&ir).expect_err("malformed assert is invalid");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::InvalidPayload {
                id: root,
                kind: IrKind::Assert,
                expected: "assert payload",
            }
        );
        assert_eq!(error.span(), span);
    }
}
