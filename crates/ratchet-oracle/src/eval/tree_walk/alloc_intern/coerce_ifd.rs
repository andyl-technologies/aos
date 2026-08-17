//! String/path coercion, path-context validation, and IFD realization.
//!
//! Owns the context-free string and filesystem-path coercion choke points,
//! the path-context and access checks they enforce, and the
//! import-from-derivation realization path that materializes a known
//! derivation closure through the configured realizer.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn attr_value_by_name(
        &mut self,
        id: IrId,
        attrs_value: Value,
        name: &[u8],
        span: Span,
    ) -> Result<Option<Value>, TreeWalkError> {
        let symbol = self.intern_symbol_for_eval(name).map_err(|source| {
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
            .get_attrs_view(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        Ok(attrs.get(symbol))
    }

    pub(in crate::eval::tree_walk) fn context_free_string_bytes(
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
            .get_string_view(value)
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

    pub(in crate::eval::tree_walk) fn coerce_to_filesystem_path_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let path = self.coerce_to_path_string(id, span, value)?;
        self.validate_filesystem_path_context(id, span, &path, op)?;
        let bytes = Self::copy_bytes_for_node(id, span, path.bytes())?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        self.realize_import_from_derivation(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        Ok(bytes)
    }

    pub(in crate::eval::tree_walk) fn coerce_to_filesystem_or_text_store_path_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<(Vec<u8>, bool), TreeWalkError> {
        let path = self.coerce_to_path_string(id, span, value)?;
        let bytes = Self::copy_bytes_for_node(id, span, path.bytes())?;
        if self.text_store_path_has_allowed_context(&path) {
            return Ok((bytes, true));
        }
        self.validate_filesystem_path_context(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        self.realize_import_from_derivation(id, span, &path, op)?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        Ok((bytes, false))
    }

    pub(in crate::eval::tree_walk) fn text_store_path_has_allowed_context(
        &self,
        path: &NixString,
    ) -> bool {
        if !self.text_store.contains_key(path.bytes()) {
            return false;
        }
        path.context().iter().all(|element| {
            element.kind() == ContextKind::OpaquePath && element.path() == path.bytes()
        })
    }

    pub(in crate::eval::tree_walk) fn coerce_to_path_string(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let path = if value.tag() == ValueTag::Path {
            self.clone_path_value(id, span, value)?
        } else {
            let string = self.coerce_to_string(id, value, span)?;
            self.clone_string_value(id, span, string)?
        };
        if !Path::new(OsStr::from_bytes(path.bytes())).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: Self::copy_bytes_for_node(id, span, path.bytes())?,
                },
                span,
            ));
        }
        Ok(path)
    }

    pub(in crate::eval::tree_walk) fn validate_filesystem_path_context(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        let normalized_path = normalize_absolute_path_bytes(path.bytes());
        for element in path.context().iter() {
            if element.kind() != ContextKind::OpaquePath {
                continue;
            }
            if !element.path().starts_with(b"/") {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
            let normalized_context_path = normalize_absolute_path_bytes(element.path());
            if !path_is_under_root(&normalized_path, &normalized_context_path) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn validate_ifd_path_context(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        for element in path.context().iter() {
            if element.kind() == ContextKind::OpaquePath {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed { id, op },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn realize_import_from_derivation(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        for element in path.context().iter() {
            match element.kind() {
                ContextKind::OpaquePath => {}
                ContextKind::SingleOutput | ContextKind::DeepDerivation => {
                    let request = IfdRealization {
                        path: path.bytes(),
                        drv_path: element.path(),
                        output_name: element.output(),
                        context_kind: element.kind(),
                        op,
                    };
                    let Some(realizer) = &self.ifd_realizer else {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::UnsupportedImportFromDerivation {
                                id,
                                op,
                                detail: Box::new(IfdErrorDetail::new(
                                    path.bytes().to_vec(),
                                    element.path().to_vec(),
                                    element.output().map(<[u8]>::to_vec),
                                    element.kind(),
                                    None,
                                )),
                            },
                            span,
                        ));
                    };
                    #[cfg(feature = "collection_poll_probe")]
                    self.final_force_ifd_realizations
                        .set(self.final_force_ifd_realizations.get().saturating_add(1));
                    self.materialize_ifd_derivation(id, span, path, element, op)?;
                    realizer.realize(request).map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ImportFromDerivation {
                                id,
                                op,
                                detail: Box::new(IfdErrorDetail::new(
                                    path.bytes().to_vec(),
                                    element.path().to_vec(),
                                    element.output().map(<[u8]>::to_vec),
                                    element.kind(),
                                    Some(source.message().to_owned()),
                                )),
                            },
                            span,
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn materialize_ifd_derivation(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
    ) -> Result<(), TreeWalkError> {
        let Some(path_in_store) = self.strip_configured_store_dir(element.path()) else {
            return Ok(());
        };
        let Ok(drv_path) = nix_compat::store_path::StorePath::<String>::from_bytes(path_in_store)
        else {
            return Ok(());
        };
        if !self.known_derivations.contains_key(&drv_path) {
            return Ok(());
        }
        let mut visited = BTreeSet::new();
        self.materialize_known_derivation_closure(
            id,
            span,
            path,
            element,
            op,
            &drv_path,
            &mut visited,
        )
    }

    pub(in crate::eval::tree_walk) fn materialize_known_derivation_closure(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
        drv_path: &nix_compat::store_path::StorePath<String>,
        visited: &mut BTreeSet<nix_compat::store_path::StorePath<String>>,
    ) -> Result<(), TreeWalkError> {
        if !visited.insert(drv_path.clone()) {
            return Ok(());
        }
        let Some(known) = self.known_derivations.get(drv_path) else {
            return Ok(());
        };
        let input_derivations: Vec<_> =
            known.derivation.input_derivations.keys().cloned().collect();
        for input in input_derivations {
            self.materialize_known_derivation_closure(
                id, span, path, element, op, &input, visited,
            )?;
        }

        let Some(known) = self.known_derivations.get(drv_path) else {
            return Ok(());
        };
        let bytes = self
            .known_derivation_aterm_bytes(drv_path, known)
            .map_err(|source| {
                self.ifd_materialization_error(id, span, path, element, op, source.to_string())
            })?;
        let absolute_path =
            PathBuf::from(OsStr::from_bytes(&self.store_path_absolute_bytes(drv_path)));
        materialize_drv(&absolute_path, &bytes).map_err(|source| {
            self.ifd_materialization_error(id, span, path, element, op, source.to_string())
        })
    }

    pub(in crate::eval::tree_walk) fn ifd_materialization_error(
        &self,
        id: IrId,
        span: Span,
        path: &NixString,
        element: &ContextElement,
        op: &'static str,
        message: String,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::ImportFromDerivation {
                id,
                op,
                detail: Box::new(IfdErrorDetail::new(
                    path.bytes().to_vec(),
                    element.path().to_vec(),
                    element.output().map(<[u8]>::to_vec),
                    element.kind(),
                    Some(format!(
                        "failed to materialize native derivation for IFD: {message}"
                    )),
                )),
            },
            span,
        )
    }

    pub(in crate::eval::tree_walk) fn check_filesystem_path_access(
        &self,
        id: IrId,
        span: Span,
        path: &[u8],
    ) -> Result<(), TreeWalkError> {
        if self.options.eval_mode() == EvalMode::Impure {
            return Ok(());
        }
        if !Path::new(OsStr::from_bytes(path)).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: path.to_vec(),
                },
                span,
            ));
        }
        let normalized = normalize_absolute_path_bytes(path);
        if self.options.path_is_allowed(&normalized) {
            if let Some(resolved) = canonicalize_policy_path(path)
                && !self.options.resolved_path_is_allowed(&resolved)
            {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::PathAccessDenied {
                        id,
                        path: resolved,
                        mode: self.options.eval_mode(),
                    },
                    span,
                ));
            }
            return Ok(());
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::PathAccessDenied {
                id,
                path: normalized,
                mode: self.options.eval_mode(),
            },
            span,
        ))
    }
}
