//! Conservative pre-run totality checks for native evaluation.
//!
//! The analysis follows only demand that strict JSON conversion proves and
//! only import targets written as uninterpolated path literals. Dynamic,
//! conditional, and unused imports remain the evaluator's responsibility, so
//! this pass cannot reject a terminating expression merely because an
//! unreachable file happens to contain recursion.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use aos_nix_syntax::{ChildSlice, NodeData, NodeId, NodeKind, ParsedAst, Symbol, parse_str};

use crate::NativeEvalError;
use crate::eval::TreeWalkOptions;

/// Rejects source containing a demanded, statically provable binding cycle.
///
/// This source-only compatibility entry point does not follow imports. Use
/// [`reject_obvious_divergence_in_import_tree`] when evaluator path policy is
/// available.
///
/// # Errors
///
/// Returns [`NativeEvalError::StaticDivergence`] when strict JSON demand proves
/// that a recursive binding must force itself.
pub fn reject_obvious_divergence(source: &str) -> Result<(), NativeEvalError> {
    let mut analysis = Analysis::new(None);
    analysis.analyze_source(source, None, None, Demand::Json)
}

/// Rejects statically provable divergence in source and demanded literal imports.
///
/// Imported files are followed recursively only when all of these conditions
/// hold:
///
/// - strict JSON demand reaches the `import` application;
/// - the target is one uninterpolated path literal;
/// - the resolved target is permitted by `options`; and
/// - the target can be read as UTF-8 Nix source.
///
/// Any path that cannot be proven static is skipped. The parser and evaluator
/// retain authority for dynamic imports, inaccessible paths, and syntax errors.
/// Relative paths in imported files are resolved from the importing file's
/// directory, matching Nix import semantics.
///
/// # Errors
///
/// Returns [`NativeEvalError::StaticDivergence`] when strict JSON demand proves
/// a recursive binding cycle in the root source or a recursively imported file.
pub fn reject_obvious_divergence_in_import_tree(
    source: &str,
    options: &TreeWalkOptions,
) -> Result<(), NativeEvalError> {
    let root_base = options
        .path_literal_base()
        .map(|bytes| PathBuf::from(OsString::from_vec(bytes.to_vec())));
    let mut analysis = Analysis::new(Some(options));
    analysis.analyze_source(source, root_base.as_deref(), None, Demand::Json)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Demand {
    Whnf,
    Json,
}

struct Analysis<'a> {
    options: Option<&'a TreeWalkOptions>,
    visited_imports: BTreeMap<PathBuf, Demand>,
}

impl<'a> Analysis<'a> {
    fn new(options: Option<&'a TreeWalkOptions>) -> Self {
        Self {
            options,
            visited_imports: BTreeMap::new(),
        }
    }

    fn analyze_source(
        &mut self,
        source: &str,
        base: Option<&Path>,
        source_path: Option<&Path>,
        demand: Demand,
    ) -> Result<(), NativeEvalError> {
        let Ok(ast) = parse_str(source) else {
            return Ok(());
        };
        let display = source_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<expression>".to_string());
        let mut visitor = DemandVisitor {
            analysis: self,
            ast: &ast,
            source_path: display,
            base: base.map(Path::to_path_buf),
            scopes: Vec::new(),
            forcing: BTreeSet::new(),
        };
        visitor.demand(ast.root, demand)
    }

    fn analyze_import(&mut self, path: &Path, demand: Demand) -> Result<(), NativeEvalError> {
        let Some(options) = self.options else {
            return Ok(());
        };
        let requested = if path.is_dir() {
            path.join("default.nix")
        } else {
            path.to_path_buf()
        };
        let Ok(canonical) = fs::canonicalize(&requested) else {
            return Ok(());
        };
        if !options.resolved_path_is_allowed(canonical.as_os_str().as_bytes()) {
            return Ok(());
        }
        if self
            .visited_imports
            .get(&canonical)
            .is_some_and(|previous| *previous >= demand)
        {
            return Ok(());
        }
        self.visited_imports.insert(canonical.clone(), demand);
        let Ok(source) = fs::read_to_string(&canonical) else {
            return Ok(());
        };
        self.analyze_source(&source, canonical.parent(), Some(&canonical), demand)
    }
}

type Scope = BTreeMap<Symbol, Binding>;

#[derive(Clone, Copy)]
struct Binding {
    name: Symbol,
    value: NodeId,
}

struct DemandVisitor<'analysis, 'options, 'ast> {
    analysis: &'analysis mut Analysis<'options>,
    ast: &'ast ParsedAst,
    source_path: String,
    base: Option<PathBuf>,
    scopes: Vec<Scope>,
    forcing: BTreeSet<NodeId>,
}

impl DemandVisitor<'_, '_, '_> {
    fn demand(&mut self, id: NodeId, demand: Demand) -> Result<(), NativeEvalError> {
        let Some(node) = self.ast.arena.node(id) else {
            return Ok(());
        };
        match (node.kind, node.data) {
            (NodeKind::Ident, NodeData::Symbol(name)) => self.demand_identifier(name, demand),
            (NodeKind::LetIn, NodeData::LetIn { bindings, body }) => {
                let scope = self.binding_scope(bindings);
                self.scopes.push(scope);
                let result = self.demand(body, demand);
                self.scopes.pop();
                result
            }
            (NodeKind::AttrSet | NodeKind::RecAttrSet, NodeData::Children(bindings)) => {
                if demand == Demand::Json {
                    self.demand_attrset(bindings, node.kind == NodeKind::RecAttrSet)
                } else {
                    Ok(())
                }
            }
            (NodeKind::List, NodeData::Children(children)) if demand == Demand::Json => {
                self.demand_children(children, Demand::Json)
            }
            (NodeKind::Binding, NodeData::Binding { value, .. }) => self.demand(value, demand),
            (NodeKind::Inherit, NodeData::Inherit { from, names }) => {
                if let Some(from) = from {
                    // `inherit (source) name` selects from the source and
                    // therefore demands its attribute-set head. The selected
                    // value remains lazy until the surrounding result demands
                    // it.
                    self.demand(from, Demand::Whnf)
                } else {
                    // Plain `inherit name` is a binding whose value is the
                    // lexical identifier itself, resolved before a recursive
                    // let/attrset's own binding frame. The parser represents
                    // the identifier in `names`, so follow it with the
                    // surrounding demand while excluding the binding whose
                    // value is this inherit node.
                    self.demand_inherit_names(id, names, demand)
                }
            }
            (NodeKind::Interp, NodeData::Node(child)) => self.demand(child, Demand::Whnf),
            (NodeKind::Interp, NodeData::Children(children)) => {
                self.demand_children(children, Demand::Whnf)
            }
            (NodeKind::Apply, NodeData::Pair { first, second }) => {
                self.demand(first, Demand::Whnf)?;
                if self.is_import(first) {
                    // `import` is strict in its path argument. Analyze that
                    // expression for local cycles even when its value is not a
                    // statically resolvable path.
                    self.demand(second, Demand::Whnf)?;
                    if let Some(path) = self.literal_path(second) {
                        self.analysis.analyze_import(&path, demand)?;
                    }
                }
                Ok(())
            }
            (NodeKind::Select, NodeData::Select { receiver, path, .. }) => {
                self.demand(receiver, Demand::Whnf)?;
                self.demand_static_selection(receiver, path, demand)
            }
            (NodeKind::HasAttr, NodeData::HasAttr { receiver, path }) => {
                self.demand(receiver, Demand::Whnf)?;
                // `hasAttr` demands only the intermediate attrsets. The leaf
                // value is not forced merely to test its presence.
                self.demand_static_selection(receiver, path, Demand::Whnf)
            }
            (NodeKind::With, NodeData::Pair { second, .. }) => {
                // `with` does not force its scope expression until dynamic
                // lookup needs it. Its body itself is demanded.
                self.demand(second, demand)
            }
            // An assertion always demands its condition, but its body is
            // conditional on that value and therefore not statically proven.
            (NodeKind::Assert, NodeData::Pair { first, .. })
            | (NodeKind::IfThenElse, NodeData::Triple { first, .. }) => {
                self.demand(first, Demand::Whnf)
            }
            // Function arguments, branches, short-circuit operands, and lambda
            // bodies are intentionally opaque to this conservative pass.
            _ => Ok(()),
        }
    }

    fn demand_identifier(&mut self, name: Symbol, demand: Demand) -> Result<(), NativeEvalError> {
        let binding = self
            .scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(&name).copied());
        self.demand_binding(binding, demand)
    }

    fn demand_attrset(
        &mut self,
        bindings: ChildSlice,
        recursive: bool,
    ) -> Result<(), NativeEvalError> {
        let scope = recursive.then(|| self.binding_scope(bindings));
        if let Some(scope) = scope {
            self.scopes.push(scope);
        }
        let result = self.demand_children(bindings, Demand::Json);
        if recursive {
            self.scopes.pop();
        }
        result
    }

    fn demand_children(
        &mut self,
        children: ChildSlice,
        demand: Demand,
    ) -> Result<(), NativeEvalError> {
        let Ok(children) = self.ast.arena.child_slice(children) else {
            return Ok(());
        };
        for child in children {
            self.demand(*child, demand)?;
        }
        Ok(())
    }

    fn demand_inherit_names(
        &mut self,
        inherit: NodeId,
        names: ChildSlice,
        demand: Demand,
    ) -> Result<(), NativeEvalError> {
        let Ok(names) = self.ast.arena.child_slice(names) else {
            return Ok(());
        };
        for name in names {
            let Some(node) = self.ast.arena.node(*name) else {
                continue;
            };
            let (NodeKind::Ident, NodeData::Symbol(name)) = (node.kind, node.data) else {
                continue;
            };
            let binding = self.scopes.iter().rev().find_map(|scope| {
                scope
                    .get(&name)
                    .copied()
                    .filter(|binding| binding.value != inherit)
            });
            self.demand_binding(binding, demand)?;
        }
        Ok(())
    }

    fn demand_binding(
        &mut self,
        binding: Option<Binding>,
        demand: Demand,
    ) -> Result<(), NativeEvalError> {
        let Some(binding) = binding else {
            return Ok(());
        };
        if !self.forcing.insert(binding.value) {
            let name =
                String::from_utf8_lossy(self.ast.symbols.resolve(binding.name).unwrap_or_default());
            return Err(NativeEvalError::StaticDivergence {
                binding: name.into_owned(),
                source_path: self.source_path.clone(),
            });
        }
        let result = self.demand(binding.value, demand);
        self.forcing.remove(&binding.value);
        result
    }

    /// Chases a statically named selection into a literal recursive attrset.
    ///
    /// Receiver WHNF alone is insufficient for `let s = rec { x = x; }; in
    /// s.x`: the demanded cycle lives in the selected binding. This helper is
    /// deliberately limited to lexical aliases and literal attrsets so it
    /// cannot reject a value whose selected shape depends on runtime control
    /// flow.
    fn demand_static_selection(
        &mut self,
        receiver: NodeId,
        path: ChildSlice,
        demand: Demand,
    ) -> Result<(), NativeEvalError> {
        let Ok(path) = self.ast.arena.child_slice(path) else {
            return Ok(());
        };
        let Some((first, rest)) = path.split_first() else {
            return Ok(());
        };
        let Some(segment) = self.static_attr_segment(*first) else {
            return Ok(());
        };
        let Some(attrset) = self.resolve_literal_attrset(receiver, &mut BTreeSet::new()) else {
            return Ok(());
        };
        let Some(node) = self.ast.arena.node(attrset) else {
            return Ok(());
        };
        let NodeData::Children(bindings) = node.data else {
            return Ok(());
        };
        let recursive = node.kind == NodeKind::RecAttrSet;
        let scope = recursive.then(|| self.binding_scope(bindings));
        if let Some(scope) = scope {
            self.scopes.push(scope);
        }
        let binding = self.binding_scope(bindings).get(&segment).copied();
        let result = if let Some(binding) = binding {
            if rest.is_empty() {
                self.demand_binding(Some(binding), demand)
            } else {
                self.demand(binding.value, Demand::Whnf)?;
                self.demand_static_selection_ids(binding.value, rest, demand)
            }
        } else {
            Ok(())
        };
        if recursive {
            self.scopes.pop();
        }
        result
    }

    fn demand_static_selection_ids(
        &mut self,
        receiver: NodeId,
        path: &[NodeId],
        demand: Demand,
    ) -> Result<(), NativeEvalError> {
        let Some((first, rest)) = path.split_first() else {
            return Ok(());
        };
        let Some(segment) = self.static_attr_segment(*first) else {
            return Ok(());
        };
        let Some(attrset) = self.resolve_literal_attrset(receiver, &mut BTreeSet::new()) else {
            return Ok(());
        };
        let Some(node) = self.ast.arena.node(attrset) else {
            return Ok(());
        };
        let NodeData::Children(bindings) = node.data else {
            return Ok(());
        };
        let recursive = node.kind == NodeKind::RecAttrSet;
        let scope = recursive.then(|| self.binding_scope(bindings));
        if let Some(scope) = scope {
            self.scopes.push(scope);
        }
        let binding = self.binding_scope(bindings).get(&segment).copied();
        let result = if let Some(binding) = binding {
            if rest.is_empty() {
                self.demand_binding(Some(binding), demand)
            } else {
                self.demand(binding.value, Demand::Whnf)?;
                self.demand_static_selection_ids(binding.value, rest, demand)
            }
        } else {
            Ok(())
        };
        if recursive {
            self.scopes.pop();
        }
        result
    }

    fn static_attr_segment(&self, id: NodeId) -> Option<Symbol> {
        let node = self.ast.arena.node(id)?;
        match (node.kind, node.data) {
            (NodeKind::Ident | NodeKind::Str, NodeData::Symbol(symbol)) => Some(symbol),
            _ => None,
        }
    }

    fn resolve_literal_attrset(&self, id: NodeId, seen: &mut BTreeSet<NodeId>) -> Option<NodeId> {
        if !seen.insert(id) {
            return None;
        }
        let node = self.ast.arena.node(id)?;
        match (node.kind, node.data) {
            (NodeKind::AttrSet | NodeKind::RecAttrSet, _) => Some(id),
            (NodeKind::Ident, NodeData::Symbol(name)) => self
                .scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(&name))
                .and_then(|binding| self.resolve_literal_attrset(binding.value, seen)),
            (NodeKind::Binding, NodeData::Binding { value, .. }) => {
                self.resolve_literal_attrset(value, seen)
            }
            _ => None,
        }
    }

    fn binding_scope(&self, bindings: ChildSlice) -> Scope {
        let Ok(bindings) = self.ast.arena.child_slice(bindings) else {
            return Scope::new();
        };
        bindings
            .iter()
            .filter_map(|binding| simple_binding(self.ast, *binding))
            .map(|(name, value)| (name, Binding { name, value }))
            .collect()
    }

    fn is_import(&self, id: NodeId) -> bool {
        self.ast.arena.node(id).is_some_and(|node| {
            node.kind == NodeKind::Ident
                && matches!(
                    node.data,
                    NodeData::Symbol(name)
                        if self.ast.symbols.resolve(name) == Some(b"import".as_slice())
                )
        })
    }

    fn literal_path(&self, id: NodeId) -> Option<PathBuf> {
        let node = self.ast.arena.node(id)?;
        if node.kind != NodeKind::Path {
            return None;
        }
        let NodeData::Symbol(symbol) = node.data else {
            return None;
        };
        let bytes = self.ast.symbols.resolve(symbol)?;
        if bytes.starts_with(b"~") {
            return None;
        }
        let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
        if path.is_absolute() {
            Some(path)
        } else {
            self.base.as_ref().map(|base| base.join(path))
        }
    }
}

fn simple_binding(ast: &ParsedAst, id: NodeId) -> Option<(Symbol, NodeId)> {
    let NodeData::Binding { path, value } = ast.arena.node(id)?.data else {
        return None;
    };
    let path = ast.arena.child_slice(path).ok()?;
    let [segment] = path else {
        return None;
    };
    let NodeData::Symbol(name) = ast.arena.node(*segment)?.data else {
        return None;
    };
    Some((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::EvalMode;

    fn allowed_options(root: &Path) -> TreeWalkOptions {
        let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
        options
            .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
            .expect("temporary path is absolute");
        options
            .add_allowed_path(root.as_os_str().as_bytes().to_vec())
            .expect("temporary path is an allowed absolute path");
        options
    }

    #[test]
    fn rejects_demanded_direct_and_mutual_cycles() {
        let direct = reject_obvious_divergence(
            "let bottom = bottom; in { manifest.value = bottom; optionWrites = []; }",
        )
        .expect_err("demanded cycle must be proven before evaluation");
        assert!(matches!(
            direct,
            NativeEvalError::StaticDivergence { ref binding, .. } if binding == "bottom"
        ));

        let mutual = reject_obvious_divergence("let a = b; b = a; in { value = a; }")
            .expect_err("demanded mutual cycle must be proven before evaluation");
        assert!(matches!(mutual, NativeEvalError::StaticDivergence { .. }));

        let selected = reject_obvious_divergence(
            "let s = rec { x = x; }; in { manifest.value = s.x; optionWrites = []; }",
        )
        .expect_err("a demanded recursive attribute selection must be proven");
        assert!(matches!(
            selected,
            NativeEvalError::StaticDivergence { ref binding, .. } if binding == "x"
        ));
    }

    #[test]
    fn does_not_reject_unused_or_conditional_cycle() {
        reject_obvious_divergence("let bottom = bottom; in 1")
            .expect("unused recursive aliases are valid laziness");
        reject_obvious_divergence("let bottom = bottom; in if true then 1 else bottom")
            .expect("the conservative analysis does not reason across conditionals");
    }

    #[test]
    fn plain_inherit_resolves_before_a_recursive_binding_frame() {
        reject_obvious_divergence("let value = 1; in rec { inherit value; }")
            .expect("plain inherit reads the outer lexical binding");
        reject_obvious_divergence("{ inherit builtins; }")
            .expect("plain inherit may read an unbound global");
    }

    #[test]
    fn follows_recursively_imported_demanded_modules() {
        let root = tempfile::tempdir().expect("temporary directory");
        let nested = root.path().join("nested");
        fs::create_dir(&nested).expect("nested directory");
        fs::write(
            nested.join("default.nix"),
            "let bottom = bottom; in { value = bottom; }",
        )
        .expect("write divergent module");
        fs::write(
            root.path().join("entry.nix"),
            "let child = import ./nested; in { inherit child; }",
        )
        .expect("write importing module");

        let options = allowed_options(root.path());
        let source = "import ./entry.nix";
        let error = reject_obvious_divergence_in_import_tree(source, &options)
            .expect_err("demanded imported divergence must be rejected before evaluation");
        assert!(matches!(
            error,
            NativeEvalError::StaticDivergence { ref binding, ref source_path }
                if binding == "bottom" && source_path.ends_with("nested/default.nix")
        ));

        let evaluator = crate::NixNative::with_options(0, options)
            .expect("native evaluator accepts totality test policy");
        let error = evaluator
            .eval_expr(source)
            .expect_err("production strict-JSON entry point must run the preflight");
        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::StaticDivergence { source_path, .. })
                if source_path.ends_with("nested/default.nix")
        ));
    }

    #[test]
    fn follows_selected_recursive_attribute_inside_imported_module() {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::write(
            root.path().join("selected.nix"),
            "let s = rec { x = x; }; in s.x",
        )
        .expect("write selected divergent module");
        let options = allowed_options(root.path());

        let error = reject_obvious_divergence_in_import_tree("import ./selected.nix", &options)
            .expect_err("demanded selected recursion in an import must be rejected");
        assert!(matches!(
            error,
            NativeEvalError::StaticDivergence { ref binding, ref source_path }
                if binding == "x" && source_path.ends_with("selected.nix")
        ));
    }

    #[test]
    fn leaves_unused_and_dynamic_imports_to_the_evaluator() {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::write(
            root.path().join("divergent.nix"),
            "let bottom = bottom; in { value = bottom; }",
        )
        .expect("write divergent module");
        fs::write(root.path().join("benign.nix"), "{ value = 1; }").expect("write benign module");
        let options = allowed_options(root.path());

        reject_obvious_divergence_in_import_tree(
            "let unused = import ./divergent.nix; in import ./benign.nix",
            &options,
        )
        .expect("unused imports are not demanded");
        reject_obvious_divergence_in_import_tree(
            "let target = if true then ./benign.nix else ./divergent.nix; in import target",
            &options,
        )
        .expect("dynamic imports are not guessed by static analysis");

        let evaluator = crate::NixNative::with_options(0, options)
            .expect("native evaluator accepts totality test policy");
        assert_eq!(
            evaluator
                .eval_expr(
                    "let target = if true then ./benign.nix else ./divergent.nix; in import target"
                )
                .expect("benign dynamic import evaluates normally"),
            r#"{"value":1}"#
        );
    }

    #[test]
    fn weak_head_library_import_does_not_force_unselected_fields() {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::write(
            root.path().join("library.nix"),
            "rec { used = 1; bottom = bottom; }",
        )
        .expect("write lazy library");
        let options = allowed_options(root.path());

        reject_obvious_divergence_in_import_tree("(import ./library.nix).used", &options)
            .expect("selecting a benign field must not force unrelated recursive fields");
        let evaluator = crate::NixNative::with_options(0, options)
            .expect("native evaluator accepts totality test policy");
        assert_eq!(
            evaluator
                .eval_expr("(import ./library.nix).used")
                .expect("selected library field evaluates normally"),
            "1"
        );
    }
}
