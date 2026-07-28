//! Report-only census for right-biased dynamic-key attribute folds.
//!
//! The probe recognizes the semantic transducer
//! `foldl' (acc: decl: acc // { ${concatStringsSep "." decl.path} = decl; }) {} xs`
//! without consulting source bytes, source spans, binder names, or physical
//! frame slots. Admission combines explicit structural roles with a
//! binder-aware semantic-slice certificate. Runtime observation happens only
//! after the ordinary fold completes and peeks already-cached values; it never
//! forces, allocates evaluator values, publishes a result, or widens execution.

use super::*;
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};

const MAX_READY_CHAIN_DEPTH: usize = 64;

static ENABLED: OnceLock<bool> = OnceLock::new();
static REFERENCE: OnceLock<Option<Box<[u8]>>> = OnceLock::new();
static FOLD_OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static STRUCTURAL_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static SEMANTIC_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static SEMANTIC_ANALYSIS_ERRORS: AtomicU64 = AtomicU64::new(0);
static SEMANTIC_ANALYSIS_ERROR_DEBUG: Mutex<Option<String>> = Mutex::new(None);
static REFERENCE_DECLINES: AtomicU64 = AtomicU64::new(0);
static CERTIFICATE_DECLINES: AtomicU64 = AtomicU64::new(0);
static RUNTIME_OPERATOR_DECLINES: AtomicU64 = AtomicU64::new(0);
static ADMITTED_CALLS: AtomicU64 = AtomicU64::new(0);
static COMPLETED_PROJECTIONS: AtomicU64 = AtomicU64::new(0);
static ELEMENTS: AtomicU64 = AtomicU64::new(0);
static MAX_ELEMENTS: AtomicU64 = AtomicU64::new(0);
static DISTINCT_KEYS: AtomicU64 = AtomicU64::new(0);
static DUPLICATE_KEYS: AtomicU64 = AtomicU64::new(0);
static PATH_ELEMENTS: AtomicU64 = AtomicU64::new(0);
static CUMULATIVE_COPIED_ENTRIES: AtomicU64 = AtomicU64::new(0);
static CONSERVATIVE_TRAFFIC_BYTES: AtomicU64 = AtomicU64::new(0);
static ENTRY_NOT_READY_DECLINES: AtomicU64 = AtomicU64::new(0);
static ENTRY_NOT_ATTRS_DECLINES: AtomicU64 = AtomicU64::new(0);
static PATH_NOT_READY_DECLINES: AtomicU64 = AtomicU64::new(0);
static PATH_NOT_LIST_DECLINES: AtomicU64 = AtomicU64::new(0);
static PATH_ELEMENT_NOT_READY_DECLINES: AtomicU64 = AtomicU64::new(0);
static PATH_ELEMENT_NOT_STRING_DECLINES: AtomicU64 = AtomicU64::new(0);
static PATH_CONTEXT_DECLINES: AtomicU64 = AtomicU64::new(0);
static PROJECTION_ALLOCATION_DECLINES: AtomicU64 = AtomicU64::new(0);

/// Source-independent structural roles for one admitted option-map fold.
#[derive(Clone, Copy, Debug)]
pub(super) struct OptionMapFoldPlan {
    operator_root: IrId,
    operator_pattern: IrId,
    operator_body: IrId,
    operator_frame: FrameId,
    path_symbol: Symbol,
}

#[derive(Clone, Copy, Debug)]
enum RuntimeProjectionDecline {
    EntryNotReady,
    EntryNotAttrs,
    PathNotReady,
    PathNotList,
    PathElementNotReady,
    PathElementNotString,
    PathContext,
    Allocation,
}

fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("AOS_NIX_OPTION_MAP_FOLD_PROBE").is_some_and(|value| value == "1")
    })
}

impl TreeWalk {
    /// Records an admitted fold and returns its immutable report-only plan.
    pub(super) fn observe_option_map_fold(
        &mut self,
        fold: IrId,
        operator: Value,
        element_count: usize,
    ) -> Option<OptionMapFoldPlan> {
        if !enabled() {
            return None;
        }
        FOLD_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
        let key = EvalNodeRef::new(self.current_module, fold);
        let plan = if let Some(plan) = self.option_map_fold_probe_plans.get(&key) {
            *plan
        } else {
            let plan = self.match_option_map_fold(fold);
            self.option_map_fold_probe_plans.insert(key, plan);
            plan
        }?;
        let Ok(lambda) = self.heap.get_lambda(operator) else {
            RUNTIME_OPERATOR_DECLINES.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if lambda.module() != self.current_module
            || !lambda.with_scope_env().is_empty()
            || !lambda.scoped_global_env().is_empty()
            || lambda.pattern() != plan.operator_pattern
            || lambda.body() != plan.operator_body
            || lambda.frame() != plan.operator_frame
        {
            RUNTIME_OPERATOR_DECLINES.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        ADMITTED_CALLS.fetch_add(1, Ordering::Relaxed);
        let count = u64::try_from(element_count).unwrap_or(u64::MAX);
        ELEMENTS.fetch_add(count, Ordering::Relaxed);
        MAX_ELEMENTS.fetch_max(count, Ordering::Relaxed);
        Some(plan)
    }

    /// Projects copied-entry traffic from values the ordinary fold already forced.
    pub(super) fn finish_option_map_fold_probe(
        &self,
        plan: Option<OptionMapFoldPlan>,
        elements: &[Value],
    ) {
        let Some(plan) = plan else {
            return;
        };
        let mut keys = HashSet::<Vec<u8>>::new();
        if keys.try_reserve(elements.len()).is_err() {
            record_runtime_decline(RuntimeProjectionDecline::Allocation);
            return;
        }
        let mut distinct = 0_u64;
        let mut duplicates = 0_u64;
        let mut path_elements = 0_u64;
        let mut cumulative = 0_u64;
        for element in elements {
            let (key, key_path_elements) = match self.project_option_map_key(*element, plan) {
                Ok(projected) => projected,
                Err(reason) => {
                    record_runtime_decline(reason);
                    return;
                }
            };
            path_elements = path_elements.saturating_add(key_path_elements);
            if keys.insert(key) {
                distinct = distinct.saturating_add(1);
            } else {
                duplicates = duplicates.saturating_add(1);
            }
            cumulative = cumulative.saturating_add(distinct);
        }
        let per_entry = std::mem::size_of::<AttrEntry>()
            .saturating_add(2_usize.saturating_mul(std::mem::size_of::<u32>()));
        let traffic = cumulative.saturating_mul(u64::try_from(per_entry).unwrap_or(u64::MAX));
        DISTINCT_KEYS.fetch_add(distinct, Ordering::Relaxed);
        DUPLICATE_KEYS.fetch_add(duplicates, Ordering::Relaxed);
        PATH_ELEMENTS.fetch_add(path_elements, Ordering::Relaxed);
        CUMULATIVE_COPIED_ENTRIES.fetch_add(cumulative, Ordering::Relaxed);
        CONSERVATIVE_TRAFFIC_BYTES.fetch_add(traffic, Ordering::Relaxed);
        COMPLETED_PROJECTIONS.fetch_add(1, Ordering::Relaxed);
    }

    /// Emits and clears accumulated report-only counts.
    pub(super) fn emit_option_map_fold_probe_report(&self) {
        if !enabled() {
            return;
        }
        let semantic_analysis_error_debug = match SEMANTIC_ANALYSIS_ERROR_DEBUG.lock() {
            Ok(mut debug) => debug.take().unwrap_or_default(),
            Err(_) => String::from("semantic-analysis diagnostic mutex poisoned"),
        };
        eprintln!(
            "aos_nix_option_map_fold_probe \
             {{\"mode\":\"report-only\",\"executes\":false,\
             \"fold_observations\":{},\"structural_admissions\":{},\
             \"semantic_admissions\":{},\"semantic_analysis_errors\":{},\
             \"semantic_analysis_error_debug\":{:?},\"reference_declines\":{},\
             \"certificate_declines\":{},\"runtime_operator_declines\":{},\
             \"admitted_calls\":{},\"completed_projections\":{},\
             \"elements\":{},\"max_elements\":{},\"distinct_keys\":{},\
             \"duplicate_keys\":{},\"path_elements\":{},\
             \"cumulative_copied_entries\":{},\
             \"conservative_entry_bytes\":{},\
             \"entry_not_ready_declines\":{},\"entry_not_attrs_declines\":{},\
             \"path_not_ready_declines\":{},\"path_not_list_declines\":{},\
             \"path_element_not_ready_declines\":{},\
             \"path_element_not_string_declines\":{},\
             \"path_context_declines\":{},\"allocation_declines\":{},\
             \"entry_byte_lower_bound\":{}}}",
            FOLD_OBSERVATIONS.swap(0, Ordering::Relaxed),
            STRUCTURAL_ADMISSIONS.swap(0, Ordering::Relaxed),
            SEMANTIC_ADMISSIONS.swap(0, Ordering::Relaxed),
            SEMANTIC_ANALYSIS_ERRORS.swap(0, Ordering::Relaxed),
            semantic_analysis_error_debug,
            REFERENCE_DECLINES.swap(0, Ordering::Relaxed),
            CERTIFICATE_DECLINES.swap(0, Ordering::Relaxed),
            RUNTIME_OPERATOR_DECLINES.swap(0, Ordering::Relaxed),
            ADMITTED_CALLS.swap(0, Ordering::Relaxed),
            COMPLETED_PROJECTIONS.swap(0, Ordering::Relaxed),
            ELEMENTS.swap(0, Ordering::Relaxed),
            MAX_ELEMENTS.swap(0, Ordering::Relaxed),
            DISTINCT_KEYS.swap(0, Ordering::Relaxed),
            DUPLICATE_KEYS.swap(0, Ordering::Relaxed),
            PATH_ELEMENTS.swap(0, Ordering::Relaxed),
            CUMULATIVE_COPIED_ENTRIES.swap(0, Ordering::Relaxed),
            CONSERVATIVE_TRAFFIC_BYTES.swap(0, Ordering::Relaxed),
            ENTRY_NOT_READY_DECLINES.swap(0, Ordering::Relaxed),
            ENTRY_NOT_ATTRS_DECLINES.swap(0, Ordering::Relaxed),
            PATH_NOT_READY_DECLINES.swap(0, Ordering::Relaxed),
            PATH_NOT_LIST_DECLINES.swap(0, Ordering::Relaxed),
            PATH_ELEMENT_NOT_READY_DECLINES.swap(0, Ordering::Relaxed),
            PATH_ELEMENT_NOT_STRING_DECLINES.swap(0, Ordering::Relaxed),
            PATH_CONTEXT_DECLINES.swap(0, Ordering::Relaxed),
            PROJECTION_ALLOCATION_DECLINES.swap(0, Ordering::Relaxed),
            std::mem::size_of::<AttrEntry>() + 2 * std::mem::size_of::<u32>(),
        );
    }

    fn match_option_map_fold(&self, fold: IrId) -> Option<OptionMapFoldPlan> {
        let module = self.modules.get(self.current_module.index())?;
        let plan = extract_option_map_fold_roles(&module.ir, &self.symbols, fold)?;
        STRUCTURAL_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
        let Some(reference) = REFERENCE.get_or_init(trusted_reference).as_deref() else {
            REFERENCE_DECLINES.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let candidate = match crate::compile::analyze_semantic_subslice_with_symbols(
            &module.ir,
            &self.symbols,
            plan.operator_root,
        ) {
            Ok(candidate) => candidate,
            Err(error) => {
                SEMANTIC_ANALYSIS_ERRORS.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut debug) = SEMANTIC_ANALYSIS_ERROR_DEBUG.lock()
                    && debug.is_none()
                {
                    *debug = Some(format!("{error:?}"));
                }
                return None;
            }
        };
        if candidate.canonical_bytes() != reference {
            CERTIFICATE_DECLINES.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SEMANTIC_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
        Some(plan)
    }

    fn project_option_map_key(
        &self,
        element: Value,
        plan: OptionMapFoldPlan,
    ) -> Result<(Vec<u8>, u64), RuntimeProjectionDecline> {
        let element = self
            .peek_option_map_ready_value(element)
            .ok_or(RuntimeProjectionDecline::EntryNotReady)?;
        let attrs = self
            .heap
            .get_attrs(element)
            .map_err(|_| RuntimeProjectionDecline::EntryNotAttrs)?;
        let path = attrs
            .get(plan.path_symbol)
            .ok_or(RuntimeProjectionDecline::EntryNotAttrs)?;
        let path = self
            .peek_option_map_ready_value(path)
            .ok_or(RuntimeProjectionDecline::PathNotReady)?;
        let path = self
            .heap
            .get_list(path)
            .map_err(|_| RuntimeProjectionDecline::PathNotList)?;
        let mut key = Vec::new();
        for (index, element) in path.as_slice().iter().enumerate() {
            let element = self
                .peek_option_map_ready_value(*element)
                .ok_or(RuntimeProjectionDecline::PathElementNotReady)?;
            let string = self
                .heap
                .get_string(element)
                .map_err(|_| RuntimeProjectionDecline::PathElementNotString)?;
            if !string.context().is_empty() {
                return Err(RuntimeProjectionDecline::PathContext);
            }
            if index != 0 {
                key.try_reserve(1)
                    .map_err(|_| RuntimeProjectionDecline::Allocation)?;
                key.push(b'.');
            }
            key.try_reserve(string.bytes().len())
                .map_err(|_| RuntimeProjectionDecline::Allocation)?;
            key.extend_from_slice(string.bytes());
        }
        Ok((key, u64::try_from(path.len()).unwrap_or(u64::MAX)))
    }

    fn peek_option_map_ready_value(&self, value: Value) -> Option<Value> {
        let mut current = value;
        for _ in 0..MAX_READY_CHAIN_DEPTH {
            if current.tag() != ValueTag::Thunk {
                return Some(current);
            }
            current = self
                .heap
                .get_thunk(current)
                .ok()?
                .cell()
                .cached_value()
                .ok()??;
        }
        None
    }
}

fn record_runtime_decline(reason: RuntimeProjectionDecline) {
    let counter = match reason {
        RuntimeProjectionDecline::EntryNotReady => &ENTRY_NOT_READY_DECLINES,
        RuntimeProjectionDecline::EntryNotAttrs => &ENTRY_NOT_ATTRS_DECLINES,
        RuntimeProjectionDecline::PathNotReady => &PATH_NOT_READY_DECLINES,
        RuntimeProjectionDecline::PathNotList => &PATH_NOT_LIST_DECLINES,
        RuntimeProjectionDecline::PathElementNotReady => &PATH_ELEMENT_NOT_READY_DECLINES,
        RuntimeProjectionDecline::PathElementNotString => &PATH_ELEMENT_NOT_STRING_DECLINES,
        RuntimeProjectionDecline::PathContext => &PATH_CONTEXT_DECLINES,
        RuntimeProjectionDecline::Allocation => &PROJECTION_ALLOCATION_DECLINES,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

fn trusted_reference() -> Option<Box<[u8]>> {
    let source = r#"let declarations = []; in builtins.foldl'
      (state: declaration:
        let joined = builtins.concatStringsSep "." declaration.path;
        in state // { ${joined} = declaration; })
      {} declarations"#;
    let parsed = crate::syntax::parse_str(source).ok()?;
    let resolved = crate::compile::resolve(parsed).ok()?;
    let mut ir = aos_nix_dialect::nix_lower(resolved).ok()?;
    crate::compile::annotate_import_ir(&mut ir).ok()?;
    let mut plans = ir.arena.nodes().iter().enumerate().filter_map(|(raw, _)| {
        let fold = IrId::new(u32::try_from(raw).ok()?);
        extract_option_map_fold_roles(&ir, &ir.symbols, fold)
    });
    let plan = plans.next()?;
    if plans.next().is_some() {
        return None;
    }
    let certificate = crate::compile::analyze_semantic_subslice(&ir, plan.operator_root).ok()?;
    Some(certificate.canonical_bytes().into())
}

fn extract_option_map_fold_roles(
    ir: &Ir,
    symbols: &SymbolTable,
    fold: IrId,
) -> Option<OptionMapFoldPlan> {
    let fold_node = ir.arena.node(fold)?;
    let IrData::PrimOp { symbol, args } = fold_node.data else {
        return None;
    };
    if fold_node.kind != IrKind::PrimOp || symbols.resolve(symbol)? != b"foldl'" {
        return None;
    }
    let [operator_id, initial_id, list_id] = ir.arena.child_slice(args)? else {
        return None;
    };
    let initial = ir.arena.node(*initial_id)?;
    let IrData::AttrSet {
        bindings: initial_bindings,
        recursive: false,
        has_dynamic: false,
        ..
    } = initial.data
    else {
        return None;
    };
    if initial.kind != IrKind::AttrSet || !initial_bindings.is_empty() {
        return None;
    }
    lexical_coordinate(ir, *list_id)?;

    let operator = ir.arena.node(*operator_id)?;
    let IrData::Lambda {
        pattern,
        body: inner_id,
        frame: Some(frame),
    } = operator.data
    else {
        return None;
    };
    let inner = ir.arena.node(inner_id)?;
    let IrData::Lambda {
        body: body_let_id,
        frame: Some(_),
        ..
    } = inner.data
    else {
        return None;
    };
    let body_let = ir.arena.node(body_let_id)?;
    let IrData::Let {
        bindings,
        body,
        frame: Some(_),
    } = body_let.data
    else {
        return None;
    };
    let let_bindings = binding_slice(ir, bindings)?;
    let body = ir.arena.node(body)?;
    let IrData::Binary {
        op: BinOpKind::Update,
        lhs,
        rhs,
    } = body.data
    else {
        return None;
    };
    if body.kind != IrKind::BinOp || lexical_coordinate(ir, lhs)? != (2, 0) {
        return None;
    }
    let rhs = ir.arena.node(rhs)?;
    let IrData::AttrSet {
        bindings,
        recursive: false,
        has_dynamic: true,
        ..
    } = rhs.data
    else {
        return None;
    };
    let [binding] = binding_slice(ir, bindings)? else {
        return None;
    };
    let IrAttrPathSegment::Dynamic(dynamic_key_id) = binding.key else {
        return None;
    };
    let dynamic_key = ir.arena.node(dynamic_key_id)?;
    let IrData::Node(key_id) = dynamic_key.data else {
        return None;
    };
    let (key_depth, key_slot) = lexical_coordinate(ir, key_id)?;
    if dynamic_key.kind != IrKind::Interp || key_depth != 0 {
        return None;
    }
    let value_body = thunk_body(ir, binding.value)?;
    if lexical_coordinate(ir, value_body)? != (1, 0) {
        return None;
    }
    let key_binding = let_bindings.get(usize::try_from(key_slot).ok()?)?;
    let key_body_id = thunk_body(ir, key_binding.value)?;
    let key_body = ir.arena.node(key_body_id)?;
    let IrData::PrimOp {
        symbol: key_symbol,
        args: key_args,
    } = key_body.data
    else {
        return None;
    };
    if key_body.kind != IrKind::PrimOp || symbols.resolve(key_symbol)? != b"concatStringsSep" {
        return None;
    }
    let [separator_id, path_id] = ir.arena.child_slice(key_args)? else {
        return None;
    };
    let separator = ir.arena.node(*separator_id)?;
    let IrData::Symbol(separator_symbol) = separator.data else {
        return None;
    };
    if separator.kind != IrKind::Str || symbols.resolve(separator_symbol)? != b"." {
        return None;
    }
    let (path_depth, path_slot, path_symbol) =
        direct_select_owner_coordinate(ir, symbols, *path_id, b"path")?;
    if (path_depth, path_slot) != (1, 0) {
        return None;
    }
    Some(OptionMapFoldPlan {
        operator_root: *operator_id,
        operator_pattern: pattern,
        operator_body: inner_id,
        operator_frame: frame,
        path_symbol,
    })
}

fn binding_slice(ir: &Ir, slice: IrBindingSlice) -> Option<&[IrBinding]> {
    let start = usize::try_from(slice.start).ok()?;
    ir.bindings
        .get(start..start.checked_add(usize::try_from(slice.len).ok()?)?)
}

fn thunk_body(ir: &Ir, id: IrId) -> Option<IrId> {
    let thunk = ir.arena.node(id)?;
    let IrData::Node(body) = thunk.data else {
        return None;
    };
    (thunk.kind == IrKind::ThunkAlloc).then_some(body)
}

fn lexical_coordinate(ir: &Ir, id: IrId) -> Option<(usize, u32)> {
    let node = ir.arena.node(id)?;
    match node.data {
        IrData::Local { slot } if node.kind == IrKind::LocalVar => Some((0, slot)),
        IrData::Upval { depth, slot } if node.kind == IrKind::UpvalVar => {
            Some((usize::try_from(depth).ok()?, slot))
        }
        _ => None,
    }
}

fn direct_select_owner_coordinate(
    ir: &Ir,
    symbols: &SymbolTable,
    id: IrId,
    expected_name: &[u8],
) -> Option<(usize, u32, Symbol)> {
    let select = ir.arena.node(id)?;
    let IrData::Select {
        receiver,
        path,
        default: None,
        ..
    } = select.data
    else {
        return None;
    };
    let [IrAttrPathSegment::Static(symbol)] = ir.attr_paths.get(path.index())?.as_ref() else {
        return None;
    };
    if select.kind != IrKind::Select || symbols.resolve(*symbol)? != expected_name {
        return None;
    }
    let (depth, slot) = lexical_coordinate(ir, receiver)?;
    Some((depth, slot, *symbol))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(source: &str) -> Ir {
        let parsed = crate::syntax::parse_str(source).expect("source parses");
        let resolved = crate::compile::resolve(parsed).expect("source resolves");
        let mut ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        crate::compile::annotate_import_ir(&mut ir).expect("source annotates");
        ir
    }

    fn admitted(source: &str) -> bool {
        let ir = lower(source);
        ir.arena.nodes().iter().enumerate().any(|(raw, _)| {
            let fold = IrId::new(raw as u32);
            let Some(plan) = extract_option_map_fold_roles(&ir, &ir.symbols, fold) else {
                return false;
            };
            let Some(reference) = trusted_reference() else {
                return false;
            };
            crate::compile::analyze_semantic_subslice(&ir, plan.operator_root)
                .is_ok_and(|slice| slice.canonical_bytes() == reference.as_ref())
        })
    }

    #[test]
    fn admits_alpha_renamed_relocated_option_map_fold() {
        assert!(admitted(
            "let unused = 7; xs = []; in builtins.foldl'
             (tree: item: let ignored = item; dotted = builtins.concatStringsSep \".\" item.path;
              in tree // { ${dotted} = item; }) {} xs"
        ));
    }

    #[test]
    fn rejects_reversed_update_bias() {
        assert!(!admitted(
            "let xs = []; in builtins.foldl'
             (acc: decl: let key = builtins.concatStringsSep \".\" decl.path;
              in { ${key} = decl; } // acc) {} xs"
        ));
    }

    #[test]
    fn rejects_changed_key_role() {
        assert!(!admitted(
            "let xs = []; in builtins.foldl'
             (acc: decl: let key = builtins.concatStringsSep \"/\" decl.name;
              in acc // { ${key} = decl; }) {} xs"
        ));
    }

    #[test]
    fn rejects_changed_accumulator_or_lazy_leaf_role() {
        assert!(!admitted(
            "let xs = []; in builtins.foldl'
             (acc: decl: let key = builtins.concatStringsSep \".\" decl.path;
              in {} // { ${key} = decl.value; }) {} xs"
        ));
    }

    #[test]
    fn rejects_nonempty_initial_accumulator() {
        assert!(!admitted(
            "let xs = []; in builtins.foldl'
             (acc: decl: let key = builtins.concatStringsSep \".\" decl.path;
              in acc // { ${key} = decl; }) { existing = true; } xs"
        ));
    }

    #[test]
    fn admits_current_modules_nix_option_map_fold() {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("lib")
                .join("modules.nix"),
        )
        .expect("repository modules.nix is readable");
        let mut ir = lower(&source);
        let reference = trusted_reference().expect("trusted reference builds");
        let symbols = std::mem::take(&mut ir.symbols);
        let mut structural_matches = 0_usize;
        for (raw, _) in ir.arena.nodes().iter().enumerate() {
            let fold = IrId::new(raw as u32);
            let Some(plan) = extract_option_map_fold_roles(&ir, &symbols, fold) else {
                continue;
            };
            structural_matches += 1;
            let error = crate::compile::analyze_semantic_subslice(&ir, plan.operator_root)
                .expect_err("adopted module IR no longer owns semantic symbols");
            assert!(matches!(
                error,
                crate::compile::SemanticSliceError::InvalidSymbol { .. }
            ));
            let slice = crate::compile::analyze_semantic_subslice_with_symbols(
                &ir,
                &symbols,
                plan.operator_root,
            )
            .expect("live complete operator resolves through adopted symbols");
            assert_eq!(slice.canonical_bytes(), reference.as_ref());
        }
        assert_eq!(structural_matches, 1);
    }
}
