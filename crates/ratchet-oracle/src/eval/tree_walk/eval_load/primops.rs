//! `TreeWalk` import-path and store/string primop handlers, split for the §2 cap.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn eval_store_path_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        if self.options.eval_mode() == EvalMode::Pure {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::StorePathPureEval { id },
                span,
            ));
        }
        let result = {
            let string = self.heap.get_string_view(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let full_path =
                Self::absolute_path_bytes_for_node(argument, argument_span, string.bytes())?;
            self.check_filesystem_path_access(argument, argument_span, &full_path)?;
            let Some(root) = store_path_root(&full_path, self.options.store_dir()) else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StorePathNotInStore {
                        id: argument,
                        path: full_path,
                    },
                    argument_span,
                ));
            };
            let root = Self::copy_bytes_for_node(argument, argument_span, root)?;
            let store_context =
                StringContext::singleton(ContextElement::opaque_path(root).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
            let context = string
                .context()
                .try_to_owned()
                .and_then(|context| context.union(&store_context))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
                })?;
            NixString::new(full_path, context)
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(in crate::eval::tree_walk) fn eval_to_path_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string_view(string_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let bytes =
                Self::absolute_path_bytes_for_node(argument, argument_span, string.bytes())?;
            let context = string.context().try_to_owned().map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?;
            NixString::new(bytes, context)
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(in crate::eval::tree_walk) fn eval_add_drv_output_dependencies_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string_view(string_value).map_err(|source| {
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
            let Some(element) = context.iter().next() else {
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
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(in crate::eval::tree_walk) fn eval_unsafe_discard_output_dependency_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string_view(string_value).map_err(|source| {
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
            for element in string.context().iter() {
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
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(in crate::eval::tree_walk) fn eval_unsafe_discard_string_context_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string_view(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            NixString::from_bytes(Self::copy_bytes_for_node(
                argument,
                argument_span,
                string.bytes(),
            )?)
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(in crate::eval::tree_walk) fn eval_string_length_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let string = self.heap.get_string_view(string).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        self.runtime_int_value(argument, argument_span, string.len() as i64)
    }

    /// Returns the byte length of an already-forced string `value` as an integer.
    ///
    /// This is the Rust-callable behind the `aos_string_length` native tier-1
    /// helper. Native code inlines `builtins.stringLength` by forcing the argument
    /// and guarding that it is a string before calling this helper, so `value`
    /// here is always a forced string; a non-string argument is deoptimized in
    /// native code and never reaches this method. Unlike
    /// [`eval_string_length_primop`](Self::eval_string_length_primop) it does not
    /// coerce (the string-tag guard already established string-ness), which for a
    /// string value is identical since coercion is the identity there.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] with a [`TreeWalkErrorKind::Heap`] source when
    /// `value` is not a string handle owned by this evaluator's heap.
    pub fn rust_callable_aos_string_length(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self
            .heap
            .get_string_view(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        self.runtime_int_value(id, span, string.len() as i64)
    }
}
