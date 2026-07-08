//! Serialization of derivations to the store-path ATerm format.

use super::*;

impl TreeWalk {
    /// Forces root-visible derivation attrsets enough for snapshot collection.
    pub(crate) fn force_root_derivation_surfaces(
        &mut self,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let root = self.current_ir().root;
        let span = self.node(root)?.span;
        let value = self.force_derivation_surface_value(root, span, value)?;
        match value.tag() {
            ValueTag::Attrs => self.force_derivation_attrset_surface(root, span, value),
            ValueTag::List => self.force_derivation_list_element_surfaces(root, span, value),
            _ => Ok(()),
        }
    }

    fn force_derivation_surface_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_lazy_foldl_initial_value(id, span, value)?;
        let value = self.force_value(id, span, value)?;
        self.force_lazy_foldl_initial_value(id, span, value)
    }

    fn force_derivation_list_element_surfaces(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let elements = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            Self::clone_list_elements(id, span, list)?
        };

        for element in elements {
            let element = self.force_derivation_surface_value(id, span, element)?;
            if element.tag() == ValueTag::Attrs {
                self.force_derivation_attrset_surface(id, span, element)?;
            }
        }

        Ok(())
    }

    fn force_derivation_attrset_surface(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let Some(type_value) = self.attr_value_by_name(id, value, TYPE_ATTR, span)? else {
            return Ok(());
        };
        let type_value = self.force_derivation_surface_value(id, span, type_value)?;
        if type_value.tag() != ValueTag::String {
            return Ok(());
        }
        let is_derivation = {
            let string = self.heap.get_string(type_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            string.bytes() == b"derivation"
        };
        if !is_derivation {
            return Ok(());
        }

        let Some(drv_path) = self.attr_value_by_name(id, value, DRV_PATH_ATTR, span)? else {
            return Ok(());
        };
        let _drv_path = self.force_derivation_surface_value(id, span, drv_path)?;

        Ok(())
    }

    pub(super) fn deferred_placeholder_derivation_aterm_bytes(
        &self,
        id: IrId,
        span: Span,
        drv_path: &nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut out = Vec::new();
        out.extend_from_slice(b"Derive(");
        Self::write_deferred_placeholder_outputs(id, span, &mut out, drv_path, derivation)?;
        out.push(b',');
        self.write_floating_ca_input_derivations(&mut out, derivation, None);
        out.push(b',');
        self.write_aterm_input_sources(&mut out, &derivation.input_sources);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.system.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.builder.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_string_array(&mut out, derivation.arguments.iter().map(String::as_bytes));
        out.push(b',');
        Self::write_deferred_placeholder_environment(id, span, &mut out, drv_path, derivation)?;
        out.push(b')');
        Ok(out)
    }

    pub(super) fn write_deferred_placeholder_outputs(
        id: IrId,
        span: Span,
        out: &mut Vec<u8>,
        drv_path: &nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
    ) -> Result<(), TreeWalkError> {
        out.push(b'[');
        for (index, (output_name, output)) in derivation.outputs.iter().enumerate() {
            if output.ca_hash.is_some() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!(
                            "deferred output {output_name:?} unexpectedly has a content address"
                        ),
                    },
                    span,
                ));
            }
            if index > 0 {
                out.push(b',');
            }
            let placeholder = Self::downstream_output_placeholder(id, span, drv_path, output_name)?;
            out.push(b'(');
            Self::write_aterm_field(out, output_name.as_bytes(), true);
            out.push(b',');
            Self::write_aterm_field(out, &placeholder, true);
            out.push(b',');
            Self::write_aterm_field(out, b"", true);
            out.push(b',');
            Self::write_aterm_field(out, b"", true);
            out.push(b')');
        }
        out.push(b']');
        Ok(())
    }

    pub(super) fn write_deferred_placeholder_environment(
        id: IrId,
        span: Span,
        out: &mut Vec<u8>,
        drv_path: &nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
    ) -> Result<(), TreeWalkError> {
        out.push(b'[');
        for (index, (key, value)) in derivation.environment.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.push(b'(');
            Self::write_aterm_field(out, key.as_bytes(), false);
            out.push(b',');
            if derivation
                .outputs
                .get(key)
                .is_some_and(|output| output.path.is_none() && output.ca_hash.is_none())
            {
                let placeholder = Self::downstream_output_placeholder(id, span, drv_path, key)?;
                Self::write_aterm_field(out, &placeholder, true);
            } else {
                Self::write_aterm_field(out, value.as_ref(), true);
            }
            out.push(b')');
        }
        out.push(b']');
        Ok(())
    }

    pub(super) fn write_floating_ca_outputs(
        out: &mut Vec<u8>,
        derivation: &nix_compat::derivation::Derivation,
        floating_ca_output: FloatingCaOutput,
    ) {
        let hash_algo = floating_ca_output.aterm_hash_algo();
        out.push(b'[');
        for (index, output_name) in derivation.outputs.keys().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.push(b'(');
            Self::write_aterm_field(out, output_name.as_bytes(), true);
            out.push(b',');
            Self::write_aterm_field(out, b"", true);
            out.push(b',');
            Self::write_aterm_field(out, hash_algo.as_bytes(), true);
            out.push(b',');
            Self::write_aterm_field(out, b"", true);
            out.push(b')');
        }
        out.push(b']');
    }

    pub(super) fn write_impure_outputs(
        out: &mut Vec<u8>,
        derivation: &nix_compat::derivation::Derivation,
        impure_output: FloatingCaOutput,
    ) {
        let hash_algo = impure_output.aterm_hash_algo();
        out.push(b'[');
        for (index, output_name) in derivation.outputs.keys().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.push(b'(');
            Self::write_aterm_field(out, output_name.as_bytes(), true);
            out.push(b',');
            Self::write_aterm_field(out, b"", true);
            out.push(b',');
            Self::write_aterm_field(out, hash_algo.as_bytes(), true);
            out.push(b',');
            Self::write_aterm_field(out, b"impure", true);
            out.push(b')');
        }
        out.push(b']');
    }

    pub(super) fn write_floating_ca_input_derivations(
        &self,
        out: &mut Vec<u8>,
        derivation: &nix_compat::derivation::Derivation,
        input_hashes: Option<
            &BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
        >,
    ) {
        match input_hashes {
            Some(input_hashes) => {
                let replacements = Self::input_hash_replacements(derivation, input_hashes);
                out.push(b'[');
                for (index, (hash, output_names)) in replacements.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.push(b'(');
                    out.push(b'"');
                    Self::write_lower_hex(out, hash.as_bytes());
                    out.push(b'"');
                    out.push(b',');
                    Self::write_aterm_string_array(out, output_names.iter().map(String::as_bytes));
                    out.push(b')');
                }
                out.push(b']');
            }
            None => {
                out.push(b'[');
                for (index, (drv_path, output_names)) in
                    derivation.input_derivations.iter().enumerate()
                {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.push(b'(');
                    let path = self.store_path_absolute_bytes(drv_path);
                    Self::write_aterm_field(out, &path, false);
                    out.push(b',');
                    Self::write_aterm_string_array(out, output_names.iter().map(String::as_bytes));
                    out.push(b')');
                }
                out.push(b']');
            }
        }
    }

    pub(super) fn write_aterm_input_sources(
        &self,
        out: &mut Vec<u8>,
        input_sources: &BTreeSet<nix_compat::store_path::StorePath<String>>,
    ) {
        out.push(b'[');
        for (index, source) in input_sources.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            let path = self.store_path_absolute_bytes(source);
            Self::write_aterm_field(out, &path, true);
        }
        out.push(b']');
    }

    pub(super) fn write_aterm_string_array<'a>(
        out: &mut Vec<u8>,
        values: impl Iterator<Item = &'a [u8]>,
    ) {
        out.push(b'[');
        for (index, value) in values.enumerate() {
            if index > 0 {
                out.push(b',');
            }
            Self::write_aterm_field(out, value, true);
        }
        out.push(b']');
    }

    pub(super) fn write_aterm_environment<V>(out: &mut Vec<u8>, environment: &BTreeMap<String, V>)
    where
        V: AsRef<[u8]>,
    {
        out.push(b'[');
        for (index, (key, value)) in environment.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.push(b'(');
            Self::write_aterm_field(out, key.as_bytes(), false);
            out.push(b',');
            Self::write_aterm_field(out, value.as_ref(), true);
            out.push(b')');
        }
        out.push(b']');
    }

    pub(super) fn write_aterm_field(out: &mut Vec<u8>, bytes: &[u8], escape: bool) {
        out.push(b'"');
        if escape {
            Self::write_aterm_escaped_bytes(out, bytes);
        } else {
            out.extend_from_slice(bytes);
        }
        out.push(b'"');
    }

    pub(super) fn write_aterm_escaped_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        for byte in bytes {
            match *byte {
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'"' => out.extend_from_slice(b"\\\""),
                byte => out.push(byte),
            }
        }
    }

    pub(super) fn write_lower_hex(out: &mut Vec<u8>, bytes: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            out.push(HEX[usize::from(byte >> 4)]);
            out.push(HEX[usize::from(byte & 0x0f)]);
        }
    }

    pub(super) fn sha256_array(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        let mut out = [0; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub(super) fn nix_sha256_digest(bytes: &[u8]) -> NixSha256Digest {
        NixSha256Digest::from_bytes(Self::sha256_array(bytes))
    }

    pub(super) fn validate_derivation_strict_before_paths(
        &self,
        id: IrId,
        span: Span,
        derivation: &nix_compat::derivation::Derivation,
    ) -> Result<(), TreeWalkError> {
        if derivation.outputs.is_empty() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: "derivation cannot have an empty set of outputs".to_owned(),
                },
                span,
            ));
        }

        for output_name in derivation.outputs.keys() {
            Self::validate_derivation_strict_output_name(id, span, output_name)?;
        }
        let fixed_outputs = derivation
            .outputs
            .iter()
            .filter(|(_, output)| output.is_fixed())
            .map(|(output_name, _)| output_name)
            .collect::<Vec<_>>();
        if !fixed_outputs.is_empty() {
            if derivation.outputs.len() != 1 {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: "fixed-output derivations must have exactly one output".to_owned(),
                    },
                    span,
                ));
            }
            if fixed_outputs[0] != "out" {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!(
                            "fixed-output derivation output must be \"out\", not {:?}",
                            fixed_outputs[0]
                        ),
                    },
                    span,
                ));
            }
        }

        for (input_derivation_path, output_names) in &derivation.input_derivations {
            if !input_derivation_path.name().ends_with(".drv") {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!(
                            "input derivation {} is not a .drv path",
                            self.store_path_absolute_display(input_derivation_path)
                        ),
                    },
                    span,
                ));
            }
            if output_names.is_empty() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!(
                            "input derivation {} has no output names",
                            self.store_path_absolute_display(input_derivation_path)
                        ),
                    },
                    span,
                ));
            }
            for output_name in output_names {
                Self::validate_derivation_strict_input_output_name(id, span, output_name)?;
            }
        }

        if derivation.system.is_empty() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: "derivation system must not be empty".to_owned(),
                },
                span,
            ));
        }
        if derivation.builder.is_empty() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: "derivation builder must not be empty".to_owned(),
                },
                span,
            ));
        }
        for key in derivation.environment.keys() {
            if key.is_empty() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: "derivation environment key must not be empty".to_owned(),
                    },
                    span,
                ));
            }
        }

        Ok(())
    }

    pub(super) fn validate_derivation_strict_input_output_name(
        id: IrId,
        span: Span,
        output_name: &str,
    ) -> Result<(), TreeWalkError> {
        if nix_compat::store_path::validate_name(output_name.as_bytes()).is_err() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: format!("invalid input derivation output name {output_name:?}"),
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn validate_derivation_strict_declared_output_name(
        id: IrId,
        span: Span,
        output_name: &str,
    ) -> Result<(), TreeWalkError> {
        if output_name == "drvPath" {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: format!("invalid derivation output name {output_name:?}"),
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn validate_derivation_strict_output_name(
        id: IrId,
        span: Span,
        output_name: &str,
    ) -> Result<(), TreeWalkError> {
        if output_name == "drvPath"
            || nix_compat::store_path::validate_name(output_name.as_bytes()).is_err()
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: format!("invalid derivation output name {output_name:?}"),
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn missing_derivation_strict_attr(
        &mut self,
        id: IrId,
        span: Span,
        name: &[u8],
    ) -> TreeWalkError {
        match self.intern_builtin_attr_symbol(id, name, span) {
            Ok(symbol) => {
                TreeWalkError::new(TreeWalkErrorKind::MissingAttribute { id, symbol }, span)
            }
            Err(error) => error,
        }
    }

    pub(super) fn derivation_utf8_string(
        id: IrId,
        span: Span,
        field: &'static str,
        bytes: &[u8],
    ) -> Result<String, TreeWalkError> {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStringUtf8 {
                        id,
                        field,
                        bytes: bytes.to_vec(),
                        message: source.to_string(),
                    },
                    span,
                )
            })
    }

    pub(super) fn store_path_absolute_bytes<S>(
        &self,
        path: &nix_compat::store_path::StorePath<S>,
    ) -> Vec<u8>
    where
        S: AsRef<str>,
    {
        let store_dir = self.options.store_dir();
        let encoded_digest = nix_compat::nixbase32::encode(path.digest());
        let needs_slash = !store_dir.ends_with(b"/");
        let mut bytes = Vec::with_capacity(
            store_dir.len()
                + usize::from(needs_slash)
                + encoded_digest.len()
                + 1
                + path.name().as_ref().len(),
        );
        bytes.extend_from_slice(store_dir);
        if needs_slash {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(encoded_digest.as_bytes());
        bytes.push(b'-');
        bytes.extend_from_slice(path.name().as_ref().as_bytes());
        bytes
    }

    pub(super) fn store_path_absolute_display<S>(
        &self,
        path: &nix_compat::store_path::StorePath<S>,
    ) -> String
    where
        S: AsRef<str>,
    {
        String::from_utf8_lossy(&self.store_path_absolute_bytes(path)).into_owned()
    }

    pub(super) fn strip_configured_store_dir<'a>(&self, path: &'a [u8]) -> Option<&'a [u8]> {
        let store_dir = self.options.store_dir();
        if store_dir == b"/" {
            return path.strip_prefix(b"/");
        }
        if !path.starts_with(store_dir) || path.get(store_dir.len()) != Some(&b'/') {
            return None;
        }
        Some(&path[store_dir.len() + 1..])
    }

    pub(super) fn add_derivation_context_inputs(
        &self,
        id: IrId,
        span: Span,
        derivation: &mut nix_compat::derivation::Derivation,
        context: &StringContext,
    ) -> Result<(), TreeWalkError> {
        for element in context {
            let store_path = self.context_store_path(id, span, element.path())?;
            match element.kind() {
                ContextKind::OpaquePath => {
                    derivation.input_sources.insert(store_path);
                }
                ContextKind::SingleOutput => {
                    let output = element.output().ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::DerivationStrict {
                                id,
                                message: "single-output context is missing an output name"
                                    .to_owned(),
                            },
                            span,
                        )
                    })?;
                    let output =
                        Self::derivation_utf8_string(id, span, "input derivation output", output)?;
                    if let Some(known) = self.known_derivations.get(&store_path)
                        && !known.output_names.contains(&output)
                    {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::DerivationStrict {
                                id,
                                message: format!(
                                    "input derivation {} has no output {output:?}",
                                    self.store_path_absolute_display(&store_path)
                                ),
                            },
                            span,
                        ));
                    }
                    derivation
                        .input_derivations
                        .entry(store_path)
                        .or_default()
                        .insert(output);
                }
                ContextKind::DeepDerivation => {
                    let known = self.known_derivations.get(&store_path).ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::DerivationStrict {
                                id,
                                message: format!(
                                    "input derivation {} is not known",
                                    self.store_path_absolute_display(&store_path)
                                ),
                            },
                            span,
                        )
                    })?;
                    derivation
                        .input_derivations
                        .entry(store_path.clone())
                        .or_default()
                        .extend(known.output_names.iter().cloned());
                    derivation.input_sources.insert(store_path);
                }
            }
        }
        Ok(())
    }

    pub(super) fn context_store_path(
        &self,
        id: IrId,
        span: Span,
        path: &[u8],
    ) -> Result<nix_compat::store_path::StorePath<String>, TreeWalkError> {
        let path = Self::copy_bytes_for_node(id, span, path)?;
        let Some(path_in_store) = self.strip_configured_store_dir(&path) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationPath {
                    id,
                    path,
                    message: "path is not in the configured Nix store".to_owned(),
                },
                span,
            ));
        };
        nix_compat::store_path::StorePath::<String>::from_bytes(path_in_store).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::DerivationPath {
                    id,
                    path,
                    message: source.to_string(),
                },
                span,
            )
        })
    }

    pub(super) fn known_derivation_hashes_for_inputs(
        &self,
        id: IrId,
        span: Span,
        derivation: &nix_compat::derivation::Derivation,
    ) -> Result<KnownDerivationInputHashes, TreeWalkError> {
        let mut hashes = BTreeMap::new();
        let mut has_deferred = false;
        for input in derivation.input_derivations.keys() {
            let known = self.known_derivations.get(input).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!(
                            "input derivation {} is not known",
                            self.store_path_absolute_display(input)
                        ),
                    },
                    span,
                )
            })?;
            hashes.insert(input.clone(), known.hash_derivation_modulo);
            has_deferred |= known.output_resolution.has_deferred_outputs();
        }
        Ok(KnownDerivationInputHashes {
            hashes,
            has_deferred,
        })
    }

    pub(crate) fn derivation_snapshot(&self) -> Result<Vec<EvalDerivation>, TreeWalkError> {
        self.known_derivations
            .iter()
            .map(|(drv_path, known)| {
                let aterm_bytes = Some(self.known_derivation_aterm_bytes(drv_path, known)?);
                Ok(EvalDerivation::new(
                    self.store_path_absolute_display(drv_path),
                    aterm_bytes,
                ))
            })
            .collect()
    }

    /// Returns known derivation path and ATerm byte surfaces.
    pub(crate) fn derivation_surface_snapshot(
        &self,
    ) -> Result<Vec<(String, Vec<u8>)>, TreeWalkError> {
        let mut surfaces = self
            .known_derivations
            .iter()
            .map(|(drv_path, known)| {
                Ok((
                    self.store_path_absolute_display(drv_path),
                    self.known_derivation_aterm_bytes(drv_path, known)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        surfaces.sort();
        Ok(surfaces)
    }

    pub(super) fn known_derivation_aterm_bytes(
        &self,
        drv_path: &nix_compat::store_path::StorePath<String>,
        known: &KnownDerivation,
    ) -> Result<Vec<u8>, TreeWalkError> {
        if let Some(aterm_bytes) = &known.aterm_bytes {
            return Ok(aterm_bytes.clone());
        }
        match known.output_resolution {
            DerivationOutputResolution::StaticPaths => {
                Ok(self.derivation_aterm_bytes(&known.derivation))
            }
            DerivationOutputResolution::FloatingCa(floating_ca_output) => Ok(self
                .floating_ca_derivation_aterm_bytes(&known.derivation, floating_ca_output, None)),
            DerivationOutputResolution::Impure(impure_output) => {
                Ok(self.impure_derivation_aterm_bytes(&known.derivation, impure_output, None))
            }
            DerivationOutputResolution::DeferredPlaceholders => self
                .deferred_placeholder_derivation_aterm_bytes(
                    known.id,
                    known.span,
                    drv_path,
                    &known.derivation,
                ),
        }
    }

    pub(super) fn remember_derivation(
        &mut self,
        id: IrId,
        span: Span,
        drv_path: nix_compat::store_path::StorePath<String>,
        derivation: &nix_compat::derivation::Derivation,
        hash_derivation_modulo: DerivationHashModulo,
        output_resolution: DerivationOutputResolution,
        aterm_bytes: Option<Vec<u8>>,
    ) {
        let output_names = derivation.outputs.keys().cloned().collect();
        let known = KnownDerivation {
            id,
            span,
            derivation: derivation.clone(),
            hash_derivation_modulo,
            output_names,
            output_resolution,
            aterm_bytes,
        };
        // Under a parallel demand pool the surface must be visible to every
        // worker before any value carrying this derivation's context is
        // published through a thunk cell.
        self.publish_known_derivation(&drv_path, &known);
        self.known_derivations.insert(drv_path, known);
    }

    pub(super) fn alloc_derivation_strict_result(
        &mut self,
        id: IrId,
        span: Span,
        derivation: &nix_compat::derivation::Derivation,
        drv_path: &nix_compat::store_path::StorePath<String>,
        output_resolution: DerivationOutputResolution,
    ) -> Result<Value, TreeWalkError> {
        let drv_path_bytes = self.store_path_absolute_bytes(drv_path);
        let mut entries = Vec::new();
        let len = derivation.outputs.len().checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: usize::MAX,
                    },
                },
                span,
            )
        })?;
        entries.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: len },
                },
                span,
            )
        })?;

        for (output_name, output) in &derivation.outputs {
            let output_path = match output.path.as_ref() {
                Some(path) => self.store_path_absolute_bytes(path),
                None if output_resolution.has_deferred_outputs() => {
                    Self::downstream_output_placeholder(id, span, drv_path, output_name)?
                }
                None => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::DerivationStrict {
                            id,
                            message: format!("output {output_name:?} has no calculated path"),
                        },
                        span,
                    ));
                }
            };
            let context = StringContext::singleton(
                ContextElement::single_output(
                    drv_path_bytes.clone(),
                    output_name.as_bytes().to_vec(),
                )
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
                })?,
            )
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
            let value = self.alloc_derivation_strict_result_string(
                id,
                span,
                &mut entries,
                NixString::new(output_path, context),
            )?;
            let key = self.intern_builtin_attr_symbol(id, output_name.as_bytes(), span)?;
            entries.push(AttrEntry::new(key, value));
        }

        let context = StringContext::singleton(
            ContextElement::deep_derivation(drv_path_bytes.clone()).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?,
        )
        .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        let drv_path_value = self.alloc_derivation_strict_result_string(
            id,
            span,
            &mut entries,
            NixString::new(drv_path_bytes, context),
        )?;
        let drv_path_key = self.intern_builtin_attr_symbol(id, DRV_PATH_ATTR, span)?;
        entries.push(AttrEntry::new(drv_path_key, drv_path_value));

        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn alloc_derivation_strict_result_string(
        &mut self,
        id: IrId,
        span: Span,
        entries: &mut [AttrEntry],
        string: NixString,
    ) -> Result<Value, TreeWalkError> {
        self.alloc_tree_walk_string_with_attr_entry_roots(id, span, entries, string)
    }
}
