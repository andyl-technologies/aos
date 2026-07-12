use super::*;

const GET_FLAKE_SOURCE_PREFIX: &[u8] = br#"
let
  loadFlake = flakeRef: overrides:
    let
      canonicalFlakeRef = builtins.flakeRefToString (builtins.parseFlakeRef flakeRef);
      sourceInfo = builtins.fetchTree canonicalFlakeRef;
      flake = import (sourceInfo.outPath + "/flake.nix");
      declaredInputs = (flake.inputs or {}) // overrides;
      unsupportedInput = builtins.throw "aos-nix builtins.getFlake currently supports only direct string, exact url, exact url+inputs override, or exact follows inputs";
      followsSegments = follows: builtins.filter builtins.isString (builtins.split "/" follows);
      resolveFollowsRoot = segment:
        if segment == "" then unsupportedInput
        else if builtins.hasAttr segment inputs then builtins.getAttr segment inputs
        else unsupportedInput;
      resolveFollowsChild = current: segment:
        if segment == "" then unsupportedInput
        else if builtins.isAttrs current
          && builtins.hasAttr "inputs" current
          && builtins.isAttrs current.inputs
          && builtins.hasAttr segment current.inputs
        then builtins.getAttr segment current.inputs
        else unsupportedInput;
      resolveFollows = follows:
        if follows == "" then self
        else
          let segments = followsSegments follows;
          in if segments == []
            then unsupportedInput
            else builtins.foldl' resolveFollowsChild (resolveFollowsRoot (builtins.head segments)) (builtins.tail segments);
      resolveInput = name: input:
        if builtins.isString input then loadFlake input {}
        else if builtins.isAttrs input
          && builtins.attrNames input == [ "url" ]
          && builtins.isString input.url
        then loadFlake input.url {}
        else if builtins.isAttrs input
          && builtins.attrNames input == [ "inputs" "url" ]
          && builtins.isString input.url
          && builtins.isAttrs input.inputs
        then loadFlake input.url input.inputs
        else if builtins.isAttrs input
          && builtins.attrNames input == [ "follows" ]
          && builtins.isString input.follows
        then resolveFollows input.follows
        else unsupportedInput;
      inputs = builtins.mapAttrs resolveInput declaredInputs;
      outputs = flake.outputs (inputs // { inherit self; });
      metadata = sourceInfo // {
        _type = "flake";
        inherit inputs outputs sourceInfo;
        outPath = sourceInfo.outPath;
      };
      self = outputs // metadata;
    in self;
in loadFlake "#;
const GET_FLAKE_SOURCE_SUFFIX: &[u8] = br#" {}
"#;

impl BuiltinExecutor for TreeWalk {
    type Value = crate::value::Value;
    type Error = TreeWalkError;
    type Arg = EvalPrimOpArg;

    fn builtin_is_available(&self, builtin: Builtin) -> bool {
        match builtin.availability() {
            BuiltinAvailability::Always => true,
            BuiltinAvailability::ImpureCurrentSystem => {
                self.options.eval_mode() != EvalMode::Pure
                    && self.options.current_system().is_some()
            }
            BuiltinAvailability::ImpureCurrentTime => {
                self.options.eval_mode() != EvalMode::Pure && self.options.current_time().is_some()
            }
        }
    }

    fn select_builtin(
        &mut self,
        builtin: Builtin,
        id: IrId,
        span: Span,
        symbol: Symbol,
    ) -> Result<Value, TreeWalkError> {
        let eval = self;
        match builtin.execution() {
            BuiltinExecution::BuiltinsValue => eval.eval_builtins_attrset(id, span),
            BuiltinExecution::TrueValue => Ok(Value::bool(true)),
            BuiltinExecution::FalseValue => Ok(Value::bool(false)),
            BuiltinExecution::NullValue => Ok(Value::null()),
            BuiltinExecution::CurrentSystemValue => {
                let Some(current_system) = eval
                    .options
                    .current_system()
                    .filter(|_| eval.options.eval_mode() != EvalMode::Pure)
                else {
                    if eval.reject_unconfigured_impure_builtin_constant(builtin) {
                        return Err(eval.unsupported_ambient_builtin_constant(id, span));
                    }
                    return unsupported_builtin_attr(id, span, symbol);
                };
                let current_system = current_system.to_vec();
                eval.alloc_static_string(id, span, &current_system)
            }
            BuiltinExecution::CurrentTimeValue => {
                let Some(current_time) = eval
                    .options
                    .current_time()
                    .filter(|_| eval.options.eval_mode() != EvalMode::Pure)
                else {
                    if eval.reject_unconfigured_impure_builtin_constant(builtin) {
                        return Err(eval.unsupported_ambient_builtin_constant(id, span));
                    }
                    return unsupported_builtin_attr(id, span, symbol);
                };
                eval.record_impure_input(ImpureInputFingerprint::current_time());
                eval.runtime_int_value(id, span, current_time)
            }
            BuiltinExecution::StoreDirValue => {
                let store_dir = eval.options.store_dir().to_vec();
                eval.alloc_static_string(id, span, &store_dir)
            }
            BuiltinExecution::NixVersionValue => {
                eval.alloc_static_string(id, span, PINNED_NIX_VERSION)
            }
            BuiltinExecution::LangVersionValue => {
                eval.runtime_int_value(id, span, PINNED_NIX_LANG_VERSION)
            }
            BuiltinExecution::NixPathValue => eval.eval_nix_path_value(id, span),
            BuiltinExecution::Derivation => eval.eval_derivation_wrapper_lambda(id, span),
            _ if builtin.first_class_arity().is_some() => {
                eval.alloc_tree_walk_primop(id, span, EvalPrimOp::registered(symbol, builtin))
            }
            _ => unsupported_builtin_attr(id, span, symbol),
        }
    }

    fn apply_builtin_direct(
        &mut self,
        builtin: Builtin,
        call: BuiltinCall,
        node: &IrNode,
        args: &[IrId],
    ) -> Result<Value, TreeWalkError> {
        let eval = self;
        check_builtin_direct_arity(call, builtin, args.len())?;

        if builtin.execution() == BuiltinExecution::Derivation {
            let argument = args[0];
            let argument_value = eval.eval_node(argument)?;
            return eval.eval_derivation_wrapper_call(call.id, call.span, argument, argument_value);
        }

        eval.enter_call(call.id, call.span)?;
        let result = (|| match builtin.execution() {
            BuiltinExecution::DerivationStrict => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                eval.eval_derivation_strict_argument(call.id, call.span, argument, argument_span)
            }
            BuiltinExecution::Import => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_import_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::Path => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_path_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::Fetchurl => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_fetchurl_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::FetchGit => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_fetch_git_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::FetchMercurial => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                eval.eval_fetch_mercurial_primop(call, argument, argument_span, None)
            }
            BuiltinExecution::FetchTarball => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_fetch_tarball_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::FetchTree => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_fetch_tree_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::GetFlake => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                eval.eval_get_flake_primop(call, argument, argument_span, None)
            }
            BuiltinExecution::FlakeRefToString => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_flake_ref_to_string_primop(
                    call.id,
                    call.span,
                    argument,
                    argument_span,
                    value,
                )
            }
            BuiltinExecution::ParseFlakeRef => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_parse_flake_ref_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::ScopedImport => {
                let scope = args[0];
                let scope_span = eval.node(scope)?.span;
                let scope_value = eval.eval_node(scope)?;
                let argument = args[1];
                let argument_span = eval.node(argument)?.span;
                let argument_value = eval.eval_node(argument)?;
                eval.eval_scoped_import_primop(
                    call.id,
                    call.span,
                    scope,
                    scope_span,
                    scope_value,
                    argument,
                    argument_span,
                    argument_value,
                )
            }
            BuiltinExecution::StrictUnary { primop, .. } => {
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
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_lazy_node(argument)?;
                eval.eval_lazy_identity_value(argument, argument_span, value)
            }
            BuiltinExecution::StrictBinary { primop, .. } => {
                eval.eval_strict_binary_primop_direct(call, node, primop, args[0], args[1])
            }
            BuiltinExecution::FindFile => {
                let search_path = args[0];
                let search_path_span = eval.node(search_path)?.span;
                let search_path_value = eval.eval_node(search_path)?;
                let lookup = args[1];
                let lookup_span = eval.node(lookup)?.span;
                let lookup_value = eval.eval_node(lookup)?;
                eval.eval_find_file_primop(
                    call.id,
                    call.span,
                    search_path,
                    search_path_span,
                    search_path_value,
                    lookup,
                    lookup_span,
                    lookup_value,
                )
            }
            BuiltinExecution::FilterSource => {
                let path = args[1];
                let path_span = eval.node(path)?.span;
                let path_value = eval.eval_node(path)?;
                let filter = args[0];
                let filter_span = eval.node(filter)?.span;
                let filter_value = eval.eval_node(filter)?;
                eval.eval_filter_source_primop(
                    call.id,
                    call.span,
                    filter,
                    filter_span,
                    filter_value,
                    path,
                    path_span,
                    path_value,
                )
            }
            BuiltinExecution::DirectBinary(primop) => {
                eval.eval_direct_binary_primop_direct(call, node, primop, args[0], args[1])
            }
            BuiltinExecution::DirectTernary(primop) => {
                eval.eval_strict_ternary_primop_direct(call, primop, args[0], args[1], args[2])
            }
            BuiltinExecution::Sort => eval.eval_sort_primop(call.id, call.span, args[0], args[1]),
            BuiltinExecution::TryEval => eval.eval_try_eval_direct(call.id, call.span, args[0]),
            BuiltinExecution::AddErrorContext => {
                eval.eval_add_error_context_direct(call.id, call.span, args[0], args[1])
            }
            BuiltinExecution::GenericClosure => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_generic_closure_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::PathExists => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_path_exists_primop(argument, argument_span, value)
            }
            BuiltinExecution::ReadDir => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_read_dir_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::ReadFile => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_read_file_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::ReadFileType => {
                let argument = args[0];
                let argument_span = eval.node(argument)?.span;
                let value = eval.eval_node(argument)?;
                eval.eval_read_file_type_primop(call.id, call.span, argument, argument_span, value)
            }
            BuiltinExecution::ToFile => {
                let name = args[0];
                let name_span = eval.node(name)?.span;
                let name_value = eval.eval_node(name)?;
                let contents = args[1];
                let contents_span = eval.node(contents)?.span;
                eval.eval_to_file_primop(
                    call.id,
                    call.span,
                    name,
                    name_span,
                    name_value,
                    contents,
                    contents_span,
                    |eval| eval.eval_node(contents),
                )
            }
            BuiltinExecution::Seq => eval.eval_seq_primop(args[0], args[1]),
            BuiltinExecution::DeepSeq => eval.eval_deep_seq_primop(args[0], args[1]),
            BuiltinExecution::Trace { mode } => {
                if !matches!(mode, TraceMode::Verbose) || eval.options.trace_verbose() {
                    let first = args[0];
                    let first_span = eval.node(first)?.span;
                    let first_value = eval.eval_node(first)?;
                    eval.eval_trace_primop_value(
                        call.id,
                        call.span,
                        mode,
                        first,
                        first_span,
                        first_value,
                    )?;
                }
                eval.eval_lazy_node(args[1])
            }
            BuiltinExecution::Warn => {
                let message = args[0];
                let message_span = eval.node(message)?.span;
                let message_value = eval.eval_node(message)?;
                eval.eval_warn_primop_value(
                    call.id,
                    call.span,
                    message,
                    message_span,
                    message_value,
                )?;
                eval.eval_lazy_node(args[1])
            }
            BuiltinExecution::Derivation
            | BuiltinExecution::BuiltinsValue
            | BuiltinExecution::TrueValue
            | BuiltinExecution::FalseValue
            | BuiltinExecution::NullValue
            | BuiltinExecution::CurrentSystemValue
            | BuiltinExecution::CurrentTimeValue
            | BuiltinExecution::StoreDirValue
            | BuiltinExecution::NixVersionValue
            | BuiltinExecution::LangVersionValue
            | BuiltinExecution::NixPathValue => unsupported_primop(call),
        })();
        eval.leave_call();
        result
    }

    fn apply_builtin(
        &mut self,
        builtin: Builtin,
        call: BuiltinCall,
        args: &[EvalPrimOpArg],
    ) -> Result<Value, TreeWalkError> {
        let eval = self;
        check_builtin_apply_arity(call, builtin, args.len())?;

        match builtin.execution() {
            BuiltinExecution::Derivation => {
                let argument = args[0];
                eval.eval_derivation_wrapper_call(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.value(),
                )
            }
            BuiltinExecution::DerivationStrict => {
                let argument = args[0];
                eval.eval_derivation_strict_value(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    argument.value(),
                )
            }
            BuiltinExecution::Import => {
                let argument = args[0];
                let value = eval.force_primop_arg(argument)?;
                eval.eval_import_primop(call.id, call.span, argument.id(), argument.span(), value)
            }
            BuiltinExecution::Path => {
                let argument = args[0];
                let value = eval.force_primop_arg(argument)?;
                eval.eval_path_primop(call.id, call.span, argument.id(), argument.span(), value)
            }
            BuiltinExecution::Fetchurl => {
                let argument = args[0];
                eval.eval_fetchurl_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    argument.value(),
                )
            }
            BuiltinExecution::FetchGit => {
                let argument = args[0];
                eval.eval_fetch_git_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    argument.value(),
                )
            }
            BuiltinExecution::FetchMercurial => {
                let argument = args[0];
                eval.eval_fetch_mercurial_primop(
                    call,
                    argument.id(),
                    argument.span(),
                    Some(argument.value()),
                )
            }
            BuiltinExecution::FetchTarball => {
                let argument = args[0];
                eval.eval_fetch_tarball_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    argument.value(),
                )
            }
            BuiltinExecution::FetchTree => {
                let argument = args[0];
                eval.eval_fetch_tree_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    argument.value(),
                )
            }
            BuiltinExecution::GetFlake => {
                let argument = args[0];
                eval.eval_get_flake_primop(
                    call,
                    argument.id(),
                    argument.span(),
                    Some(argument.value()),
                )
            }
            BuiltinExecution::FlakeRefToString => {
                let argument = args[0];
                eval.eval_flake_ref_to_string_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    argument.value(),
                )
            }
            BuiltinExecution::ParseFlakeRef => {
                let argument = args[0];
                eval.eval_parse_flake_ref_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    argument.value(),
                )
            }
            BuiltinExecution::ScopedImport => {
                let scope = args[0];
                let scope_value = eval.force_primop_arg(scope)?;
                let argument = args[1];
                let argument_value = eval.force_primop_arg(argument)?;
                eval.eval_scoped_import_primop(
                    call.id,
                    call.span,
                    scope.id(),
                    scope.span(),
                    scope_value,
                    argument.id(),
                    argument.span(),
                    argument_value,
                )
            }
            BuiltinExecution::StrictUnary { primop, .. } => {
                let argument = args[0];
                let value = eval.force_primop_arg(argument)?;
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
                let argument = args[0];
                eval.eval_lazy_identity_value(argument.id(), argument.span(), argument.value())
            }
            BuiltinExecution::StrictBinary { primop, .. } => eval.eval_strict_binary_primop_value(
                call.id,
                call.span,
                call.symbol,
                primop,
                args[0],
                args[1],
            ),
            BuiltinExecution::FindFile => {
                let search_path = args[0];
                let search_path_value = eval.force_primop_arg(search_path)?;
                let lookup = args[1];
                let lookup_value = eval.force_primop_arg(lookup)?;
                eval.eval_find_file_primop(
                    call.id,
                    call.span,
                    search_path.id(),
                    search_path.span(),
                    search_path_value,
                    lookup.id(),
                    lookup.span(),
                    lookup_value,
                )
            }
            BuiltinExecution::FilterSource => eval.eval_filter_source_primop(
                call.id,
                call.span,
                args[0].id(),
                args[0].span(),
                args[0].value(),
                args[1].id(),
                args[1].span(),
                args[1].value(),
            ),
            BuiltinExecution::DirectBinary(primop) => {
                eval.eval_direct_binary_primop_value(call, primop, args[0], args[1])
            }
            BuiltinExecution::DirectTernary(primop) => eval.eval_strict_ternary_primop_value(
                call.id, call.span, primop, args[0], args[1], args[2],
            ),
            BuiltinExecution::Sort => {
                eval.eval_sort_primop_value(call.id, call.span, args[0], args[1])
            }
            BuiltinExecution::TryEval => eval.eval_try_eval_value(call.id, call.span, args[0]),
            BuiltinExecution::AddErrorContext => {
                eval.eval_add_error_context_value(call.id, call.span, args[0], args[1])
            }
            BuiltinExecution::GenericClosure => {
                let argument = args[0];
                eval.eval_generic_closure_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    argument.value(),
                )
            }
            BuiltinExecution::PathExists => {
                let argument = args[0];
                let value = eval.force_primop_arg(argument)?;
                eval.eval_path_exists_primop(argument.id(), argument.span(), value)
            }
            BuiltinExecution::ReadDir => {
                let argument = args[0];
                let value = eval.force_primop_arg(argument)?;
                eval.eval_read_dir_primop(call.id, call.span, argument.id(), argument.span(), value)
            }
            BuiltinExecution::ReadFile => {
                let argument = args[0];
                let value = eval.force_primop_arg(argument)?;
                eval.eval_read_file_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    value,
                )
            }
            BuiltinExecution::ReadFileType => {
                let argument = args[0];
                let value = eval.force_primop_arg(argument)?;
                eval.eval_read_file_type_primop(
                    call.id,
                    call.span,
                    argument.id(),
                    argument.span(),
                    value,
                )
            }
            BuiltinExecution::ToFile => {
                let name = args[0];
                let name_value = eval.force_primop_arg(name)?;
                let contents = args[1];
                eval.eval_to_file_primop(
                    call.id,
                    call.span,
                    name.id(),
                    name.span(),
                    name_value,
                    contents.id(),
                    contents.span(),
                    |eval| eval.force_primop_arg(contents),
                )
            }
            BuiltinExecution::Seq => {
                let first = args[0];
                let value = eval.force_primop_arg(first)?;
                eval.consume_suspended_lazy_identity_thunk(first.id(), first.span(), value)?;
                Ok(args[1].value())
            }
            BuiltinExecution::DeepSeq => {
                let first = args[0];
                let value = eval.force_primop_arg(first)?;
                if !eval.consume_suspended_lazy_identity_thunk(first.id(), first.span(), value)? {
                    let mut visited = Vec::new();
                    eval.deep_force_value(first.id(), first.span(), value, &mut visited)?;
                }
                Ok(args[1].value())
            }
            BuiltinExecution::Trace { mode } => {
                if matches!(mode, TraceMode::Verbose) && !eval.options.trace_verbose() {
                    return Ok(args[1].value());
                }
                let first = args[0];
                let value = eval.force_primop_arg(first)?;
                eval.eval_trace_primop_value(
                    call.id,
                    call.span,
                    mode,
                    first.id(),
                    first.span(),
                    value,
                )?;
                Ok(args[1].value())
            }
            BuiltinExecution::Warn => {
                let message = args[0];
                let value = eval.force_primop_arg(message)?;
                eval.eval_warn_primop_value(
                    call.id,
                    call.span,
                    message.id(),
                    message.span(),
                    value,
                )?;
                Ok(args[1].value())
            }
            BuiltinExecution::BuiltinsValue
            | BuiltinExecution::TrueValue
            | BuiltinExecution::FalseValue
            | BuiltinExecution::NullValue
            | BuiltinExecution::CurrentSystemValue
            | BuiltinExecution::CurrentTimeValue
            | BuiltinExecution::StoreDirValue
            | BuiltinExecution::NixVersionValue
            | BuiltinExecution::LangVersionValue
            | BuiltinExecution::NixPathValue => unsupported_primop(call),
        }
    }
}

impl TreeWalk {
    fn eval_get_flake_primop(
        &mut self,
        call: BuiltinCall,
        argument: IrId,
        argument_span: Span,
        value: Option<Value>,
    ) -> Result<Value, TreeWalkError> {
        let value = match value {
            Some(value) => value,
            None => self.eval_node(argument)?,
        };
        let value = self.force_demanded_value(argument, argument_span, value)?;
        let flake_ref =
            self.context_free_string_bytes(argument, argument_span, value, "getFlake")?;
        let attrs = Self::parse_flake_ref_attrs(argument, argument_span, &flake_ref)?;
        let flake_ref = self.flake_ref_attrs_to_string(argument, argument_span, &attrs)?;
        let source = Self::get_flake_source(argument, argument_span, &flake_ref)?;

        self.load_and_eval_import_bytes(
            call.id,
            call.span,
            argument,
            argument_span,
            b"<builtins.getFlake>",
            b"/",
            &source,
            ImportGlobalScope::Fresh,
        )
    }

    fn get_flake_source(id: IrId, span: Span, flake_ref: &[u8]) -> Result<Vec<u8>, TreeWalkError> {
        let literal = Self::nix_double_quoted_string(id, span, flake_ref)?;
        let len = literal
            .len()
            .checked_add(GET_FLAKE_SOURCE_PREFIX.len())
            .and_then(|len| len.checked_add(GET_FLAKE_SOURCE_SUFFIX.len()))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        let mut source = Vec::new();
        source.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        source.extend_from_slice(GET_FLAKE_SOURCE_PREFIX);
        source.extend_from_slice(&literal);
        source.extend_from_slice(GET_FLAKE_SOURCE_SUFFIX);
        Ok(source)
    }

    fn nix_double_quoted_string(
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut out = Vec::new();
        let capacity = bytes
            .len()
            .checked_mul(2)
            .and_then(|len| len.checked_add(2))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        out.try_reserve_exact(capacity).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed { id, len: capacity },
                span,
            )
        })?;
        out.push(b'"');
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'"' => out.extend_from_slice(br#"\""#),
                b'\\' => out.extend_from_slice(br#"\\"#),
                b'\n' => out.extend_from_slice(br#"\n"#),
                b'\r' => out.extend_from_slice(br#"\r"#),
                b'\t' => out.extend_from_slice(br#"\t"#),
                b'$' if bytes.get(index + 1) == Some(&b'{') => out.extend_from_slice(br#"\$"#),
                byte if byte.is_ascii_control() => {
                    return Err(Self::flake_ref_error(
                        id,
                        span,
                        bytes,
                        "flake reference cannot be embedded in getFlake source",
                    ));
                }
                byte => out.push(byte),
            }
            index += 1;
        }
        out.push(b'"');
        Ok(out)
    }
}
