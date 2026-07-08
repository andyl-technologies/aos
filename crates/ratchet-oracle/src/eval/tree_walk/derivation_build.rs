//! Derivation construction: output hashing, fixed/floating outputs, and build assembly.

use super::*;

type DerivationOutputsListValue = (
    BTreeMap<String, nix_compat::derivation::Output>,
    Vec<String>,
    StringContext,
);

impl TreeWalk {
    pub(super) fn derivation_outputs_list_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<DerivationOutputsListValue, TreeWalkError> {
        if value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: value_id,
                    expected: "list",
                    actual: value.tag(),
                },
                value_span,
            ));
        }

        let elements = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: value_id,
                        source,
                    },
                    value_span,
                )
            })?;
            Self::clone_list_elements(value_id, value_span, list)?
        };
        let mut outputs = BTreeMap::new();
        let mut output_names = Vec::new();
        output_names
            .try_reserve_exact(elements.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: value_id,
                        len: elements.len(),
                    },
                    value_span,
                )
            })?;
        let context = StringContext::empty();
        for element in elements {
            let value = self.force_value(value_id, value_span, element)?;
            let bytes =
                self.derivation_context_free_string_value(id, span, value_id, value_span, value)?;
            let output_name = Self::derivation_utf8_string(id, span, "output name", &bytes)?;
            Self::validate_derivation_strict_declared_output_name(id, span, &output_name)?;
            if outputs
                .insert(
                    output_name.clone(),
                    nix_compat::derivation::Output::default(),
                )
                .is_some()
            {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!("duplicate derivation output {output_name:?}"),
                    },
                    span,
                ));
            }
            output_names.push(output_name);
        }

        if outputs.is_empty() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: "derivation cannot have an empty set of outputs".to_owned(),
                },
                span,
            ));
        }

        Ok((outputs, output_names, context))
    }

    pub(super) fn is_derivation_outputs_separator(byte: u8) -> bool {
        matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
    }

    pub(super) fn write_structured_json_field_name(
        id: IrId,
        span: Span,
        json: &mut StructuredAttrsJson,
        key: &[u8],
    ) -> Result<(), TreeWalkError> {
        if json.has_fields {
            json.bytes.push(b',');
        }
        json.has_fields = true;
        Self::write_json_string_bytes(id, span, key, &mut json.bytes)?;
        json.bytes.push(b':');
        Ok(())
    }

    pub(super) fn write_structured_json_string_field(
        id: IrId,
        span: Span,
        json: &mut StructuredAttrsJson,
        key: &[u8],
        value: &str,
    ) -> Result<(), TreeWalkError> {
        Self::write_structured_json_field_name(id, span, json, key)?;
        Self::write_json_string_bytes(id, span, value.as_bytes(), &mut json.bytes)
    }

    pub(super) fn write_structured_json_string_list_field(
        id: IrId,
        span: Span,
        json: &mut StructuredAttrsJson,
        key: &[u8],
        values: &[String],
    ) -> Result<(), TreeWalkError> {
        Self::write_structured_json_field_name(id, span, json, key)?;
        json.bytes.push(b'[');
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                json.bytes.push(b',');
            }
            Self::write_json_string_bytes(id, span, value.as_bytes(), &mut json.bytes)?;
        }
        json.bytes.push(b']');
        Ok(())
    }

    pub(super) fn write_structured_json_value_field(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        json: &mut StructuredAttrsJson,
        key: &[u8],
        value: Value,
        context: &mut StringContext,
    ) -> Result<(), TreeWalkError> {
        Self::write_structured_json_field_name(id, span, json, key)?;
        self.write_json_value(
            id,
            span,
            value_id,
            value_span,
            value,
            &mut json.bytes,
            context,
        )
    }

    pub(super) fn configure_derivation_fixed_output(
        id: IrId,
        span: Span,
        derivation: &mut nix_compat::derivation::Derivation,
        output_hash: Option<&str>,
        output_hash_algo: Option<&str>,
        output_hash_mode: Option<&str>,
    ) -> Result<(), TreeWalkError> {
        let Some(hash) = output_hash else {
            return Ok(());
        };

        let hash_algo =
            output_hash_algo.and_then(|algo| nix_compat::nixhash::HashAlgo::try_from(algo).ok());

        let nix_hash = if hash.is_empty() {
            let hash_algo = hash_algo.ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: "empty outputHash requires explicit outputHashAlgo".to_owned(),
                    },
                    span,
                )
            })?;
            let digest = vec![0; hash_algo.digest_length()];
            nix_compat::derivation::NixHash::from_algo_and_digest(hash_algo, &digest).map_err(
                |source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::DerivationStrict {
                            id,
                            message: format!("invalid outputHash: {source}"),
                        },
                        span,
                    )
                },
            )?
        } else {
            nix_compat::derivation::NixHash::from_str(hash, hash_algo).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!("invalid outputHash: {source}"),
                    },
                    span,
                )
            })?
        };

        let ca_hash = match output_hash_mode {
            None | Some("flat") => nix_compat::derivation::CAHash::Flat(nix_hash),
            Some("recursive" | "nar") => nix_compat::derivation::CAHash::Nar(nix_hash),
            Some(mode) => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!("invalid outputHashMode {mode:?}"),
                    },
                    span,
                ));
            }
        };

        derivation
            .outputs
            .entry("out".to_owned())
            .or_default()
            .ca_hash = Some(ca_hash);
        Ok(())
    }

    pub(super) fn configure_derivation_floating_ca_output(
        id: IrId,
        span: Span,
        output_hash_algo: Option<&str>,
        output_hash_mode: Option<&str>,
    ) -> Result<FloatingCaOutput, TreeWalkError> {
        let hash_algo = output_hash_algo
            .and_then(|algo| nix_compat::nixhash::HashAlgo::try_from(algo).ok())
            .unwrap_or(nix_compat::nixhash::HashAlgo::Sha256);
        let method = match output_hash_mode {
            None | Some("recursive" | "nar") => FloatingCaMethod::Recursive,
            Some("flat") => FloatingCaMethod::Flat,
            Some(mode) => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: format!("invalid outputHashMode {mode:?}"),
                    },
                    span,
                ));
            }
        };

        Ok(FloatingCaOutput { method, hash_algo })
    }

    pub(super) fn derivation_has_fixed_output(
        derivation: &nix_compat::derivation::Derivation,
    ) -> bool {
        derivation.outputs.values().any(|output| output.is_fixed())
    }

    pub(super) fn calculate_derivation_path(
        &mut self,
        id: IrId,
        span: Span,
        name: &str,
        derivation: &nix_compat::derivation::Derivation,
    ) -> Result<nix_compat::store_path::StorePath<String>, TreeWalkError> {
        let aterm = self.derivation_aterm_bytes(derivation);
        self.calculate_derivation_path_from_aterm(id, span, name, derivation, &aterm)
    }

    pub(super) fn calculate_derivation_path_from_aterm(
        &mut self,
        id: IrId,
        span: Span,
        name: &str,
        derivation: &nix_compat::derivation::Derivation,
        aterm: &[u8],
    ) -> Result<nix_compat::store_path::StorePath<String>, TreeWalkError> {
        self.increment_derivation_text_path_calculations();
        let drv_name = format!("{name}.drv");
        let references = self.derivation_path_references(derivation);
        self.build_text_path(id, span, &drv_name, aterm, references)
    }

    pub(super) fn derivation_path_references(
        &self,
        derivation: &nix_compat::derivation::Derivation,
    ) -> BTreeSet<Vec<u8>> {
        let references: BTreeSet<Vec<u8>> = derivation
            .input_sources
            .iter()
            .chain(derivation.input_derivations.keys())
            .map(|path| self.store_path_absolute_bytes(path))
            .collect();
        references
    }

    pub(super) fn calculate_output_paths(
        &self,
        id: IrId,
        span: Span,
        name: &str,
        derivation: &mut nix_compat::derivation::Derivation,
        hash_derivation_modulo: &DerivationHashModulo,
    ) -> Result<(), TreeWalkError> {
        for (output_name, output) in derivation.outputs.iter_mut() {
            debug_assert!(output.path.is_none());
            let path_name = Self::output_path_name(name, output_name);
            let store_path = if let Some(ca_hash) = output.ca_hash.as_ref() {
                self.build_ca_path(
                    id,
                    span,
                    &path_name,
                    ca_hash,
                    std::iter::empty::<Vec<u8>>(),
                    false,
                )?
            } else {
                self.build_store_path_from_fingerprint_parts(
                    id,
                    span,
                    format!("output:{output_name}").as_bytes(),
                    hash_derivation_modulo.nix_sha256_digest(),
                    &path_name,
                )?
            };
            derivation.environment.insert(
                output_name.to_string(),
                self.store_path_absolute_bytes(&store_path).into(),
            );
            output.path = Some(store_path);
        }
        Ok(())
    }

    pub(super) fn hash_derivation_modulo_with_inputs(
        &mut self,
        id: IrId,
        span: Span,
        derivation: &nix_compat::derivation::Derivation,
        input_hashes: &BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
    ) -> Result<DerivationHashModulo, TreeWalkError> {
        self.increment_derivation_hash_calculations();
        if let Some(digest) = self.fixed_output_derivation_digest(id, span, derivation)? {
            return Ok(digest);
        }
        let aterm = self.derivation_aterm_bytes_with_input_hashes(derivation, input_hashes);
        Ok(DerivationHashModulo::from_nix_sha256_digest(
            Self::nix_sha256_digest(&aterm),
        ))
    }

    pub(super) fn fixed_output_derivation_digest(
        &self,
        id: IrId,
        span: Span,
        derivation: &nix_compat::derivation::Derivation,
    ) -> Result<Option<DerivationHashModulo>, TreeWalkError> {
        if derivation.outputs.len() != 1 {
            return Ok(None);
        }
        let Some(output) = derivation.outputs.get("out") else {
            return Ok(None);
        };
        let Some(ca_hash) = output.ca_hash.as_ref() else {
            return Ok(None);
        };
        let output_path = output
            .path
            .as_ref()
            .map(|path| self.store_path_absolute_bytes(path))
            .unwrap_or_default();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"fixed:out:");
        bytes.extend_from_slice(Self::derivation_ca_kind_prefix(id, span, ca_hash)?.as_bytes());
        bytes.extend_from_slice(ca_hash.hash().to_nix_lowerhex_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(&output_path);
        Ok(Some(DerivationHashModulo::from_nix_sha256_digest(
            Self::nix_sha256_digest(&bytes),
        )))
    }

    pub(super) fn build_text_path(
        &self,
        id: IrId,
        span: Span,
        name: &str,
        content: &[u8],
        references: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<nix_compat::store_path::StorePath<String>, TreeWalkError> {
        let content_digest = Self::nix_sha256_digest(content);
        self.build_ca_path(
            id,
            span,
            name,
            &nix_compat::derivation::CAHash::Text(content_digest.into_bytes()),
            references,
            false,
        )
    }

    pub(super) fn build_ca_path(
        &self,
        id: IrId,
        span: Span,
        name: &str,
        ca_hash: &nix_compat::derivation::CAHash,
        references: impl IntoIterator<Item = Vec<u8>>,
        self_reference: bool,
    ) -> Result<nix_compat::store_path::StorePath<String>, TreeWalkError> {
        let mut references = references.into_iter().peekable();
        let (fingerprint_type, inner_digest) = match ca_hash {
            nix_compat::derivation::CAHash::Text(digest) => (
                Self::make_references_fingerprint_type(b"text", references, false),
                NixSha256Digest::from_bytes(*digest),
            ),
            nix_compat::derivation::CAHash::Nar(nix_compat::derivation::NixHash::Sha256(
                digest,
            )) => (
                Self::make_references_fingerprint_type(b"source", references, self_reference),
                NixSha256Digest::from_bytes(*digest),
            ),
            nix_compat::derivation::CAHash::Nar(hash) => {
                if references.peek().is_some() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::DerivationStrict {
                            id,
                            message: "non-sha256 recursive fixed output references are unsupported"
                                .to_owned(),
                        },
                        span,
                    ));
                }
                (
                    b"output:out".to_vec(),
                    Self::fixed_output_path_digest(b"fixed:out:r", hash),
                )
            }
            nix_compat::derivation::CAHash::Flat(hash) => {
                if references.peek().is_some() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::DerivationStrict {
                            id,
                            message: "flat fixed output references are unsupported".to_owned(),
                        },
                        span,
                    ));
                }
                (
                    b"output:out".to_vec(),
                    Self::fixed_output_path_digest(b"fixed:out", hash),
                )
            }
        };
        self.build_store_path_from_fingerprint_parts(
            id,
            span,
            &fingerprint_type,
            inner_digest,
            name,
        )
    }

    pub(super) fn build_store_path_from_fingerprint_parts(
        &self,
        id: IrId,
        span: Span,
        fingerprint_type: &[u8],
        inner_digest: NixSha256Digest,
        name: &str,
    ) -> Result<nix_compat::store_path::StorePath<String>, TreeWalkError> {
        let digest = Self::lower_hex_bytes(id, span, inner_digest.as_bytes())?;
        let mut fingerprint = Vec::new();
        fingerprint.extend_from_slice(fingerprint_type);
        fingerprint.extend_from_slice(b":sha256:");
        fingerprint.extend_from_slice(&digest);
        fingerprint.push(b':');
        fingerprint.extend_from_slice(self.options.store_dir());
        fingerprint.push(b':');
        fingerprint.extend_from_slice(name.as_bytes());
        let fingerprint_hash = Self::sha256_array(&fingerprint);
        let digest = nix_compat::store_path::compress_hash::<{ nix_compat::store_path::DIGEST_SIZE }>(
            &fingerprint_hash,
        );
        nix_compat::store_path::StorePath::from_name_and_digest_fixed(name, digest).map_err(
            |source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::DerivationStrict {
                        id,
                        message: source.to_string(),
                    },
                    span,
                )
            },
        )
    }

    pub(super) fn make_references_fingerprint_type(
        kind: &[u8],
        references: impl IntoIterator<Item = Vec<u8>>,
        self_reference: bool,
    ) -> Vec<u8> {
        let mut out = kind.to_vec();
        for reference in references {
            out.push(b':');
            out.extend_from_slice(&reference);
        }
        if self_reference {
            out.extend_from_slice(b":self");
        }
        out
    }

    pub(super) fn fixed_output_path_digest(
        prefix: &[u8],
        hash: &nix_compat::derivation::NixHash,
    ) -> NixSha256Digest {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(prefix);
        bytes.push(b':');
        bytes.extend_from_slice(hash.to_nix_lowerhex_string().as_bytes());
        bytes.push(b':');
        Self::nix_sha256_digest(&bytes)
    }

    pub(super) fn output_path_name(derivation_name: &str, output_name: &str) -> String {
        if output_name == "out" {
            derivation_name.to_owned()
        } else {
            format!("{derivation_name}-{output_name}")
        }
    }

    pub(super) fn derivation_ca_kind_prefix(
        id: IrId,
        span: Span,
        ca_hash: &nix_compat::derivation::CAHash,
    ) -> Result<&'static str, TreeWalkError> {
        match ca_hash {
            nix_compat::derivation::CAHash::Flat(_) => Ok(""),
            nix_compat::derivation::CAHash::Nar(_) => Ok("r:"),
            nix_compat::derivation::CAHash::Text(_) => Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: "text content address is invalid for derivation outputs".to_owned(),
                },
                span,
            )),
        }
    }

    pub(super) fn hash_floating_ca_derivation_modulo_with_inputs(
        &mut self,
        derivation: &nix_compat::derivation::Derivation,
        floating_ca_output: FloatingCaOutput,
        input_hashes: &BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
    ) -> DerivationHashModulo {
        self.increment_derivation_hash_calculations();
        let aterm = self.floating_ca_derivation_aterm_bytes(
            derivation,
            floating_ca_output,
            Some(input_hashes),
        );
        DerivationHashModulo::from_nix_sha256_digest(Self::nix_sha256_digest(&aterm))
    }

    pub(super) fn impure_derivation_hash_modulo() -> DerivationHashModulo {
        DerivationHashModulo::from_nix_sha256_digest(Self::nix_sha256_digest(b"impure"))
    }

    pub(super) fn floating_ca_derivation_aterm_bytes(
        &self,
        derivation: &nix_compat::derivation::Derivation,
        floating_ca_output: FloatingCaOutput,
        input_hashes: Option<
            &BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
        >,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"Derive(");
        Self::write_floating_ca_outputs(&mut out, derivation, floating_ca_output);
        out.push(b',');
        self.write_floating_ca_input_derivations(&mut out, derivation, input_hashes);
        out.push(b',');
        self.write_aterm_input_sources(&mut out, &derivation.input_sources);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.system.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.builder.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_string_array(&mut out, derivation.arguments.iter().map(String::as_bytes));
        out.push(b',');
        Self::write_aterm_environment(&mut out, &derivation.environment);
        out.push(b')');
        out
    }

    pub(super) fn derivation_aterm_bytes(
        &self,
        derivation: &nix_compat::derivation::Derivation,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"Derive(");
        self.write_derivation_outputs(&mut out, derivation);
        out.push(b',');
        self.write_derivation_input_paths(&mut out, &derivation.input_derivations);
        out.push(b',');
        self.write_derivation_input_sources(&mut out, &derivation.input_sources);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.system.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.builder.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_string_array(&mut out, derivation.arguments.iter().map(String::as_bytes));
        out.push(b',');
        Self::write_aterm_environment(&mut out, &derivation.environment);
        out.push(b')');
        out
    }

    pub(super) fn impure_derivation_aterm_bytes(
        &self,
        derivation: &nix_compat::derivation::Derivation,
        impure_output: FloatingCaOutput,
        input_hashes: Option<
            &BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
        >,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"Derive(");
        Self::write_impure_outputs(&mut out, derivation, impure_output);
        out.push(b',');
        self.write_floating_ca_input_derivations(&mut out, derivation, input_hashes);
        out.push(b',');
        self.write_aterm_input_sources(&mut out, &derivation.input_sources);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.system.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.builder.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_string_array(&mut out, derivation.arguments.iter().map(String::as_bytes));
        out.push(b',');
        Self::write_aterm_environment(&mut out, &derivation.environment);
        out.push(b')');
        out
    }

    pub(super) fn derivation_aterm_bytes_with_input_hashes(
        &self,
        derivation: &nix_compat::derivation::Derivation,
        input_hashes: &BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
    ) -> Vec<u8> {
        let replacements = Self::input_hash_replacements(derivation, input_hashes);
        let mut out = Vec::new();
        out.extend_from_slice(b"Derive(");
        self.write_derivation_outputs(&mut out, derivation);
        out.push(b',');
        Self::write_derivation_input_hashes(&mut out, &replacements);
        out.push(b',');
        self.write_derivation_input_sources(&mut out, &derivation.input_sources);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.system.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_field(&mut out, derivation.builder.as_bytes(), true);
        out.push(b',');
        Self::write_aterm_string_array(&mut out, derivation.arguments.iter().map(String::as_bytes));
        out.push(b',');
        Self::write_aterm_environment(&mut out, &derivation.environment);
        out.push(b')');
        out
    }

    pub(super) fn input_hash_replacements(
        derivation: &nix_compat::derivation::Derivation,
        input_hashes: &BTreeMap<nix_compat::store_path::StorePath<String>, DerivationHashModulo>,
    ) -> BTreeMap<NixSha256Digest, BTreeSet<String>> {
        let mut replacements: BTreeMap<NixSha256Digest, BTreeSet<String>> = BTreeMap::new();
        for (drv_path, outputs) in &derivation.input_derivations {
            let Some(hash) = input_hashes.get(drv_path) else {
                continue;
            };
            replacements
                .entry(hash.nix_sha256_digest())
                .or_default()
                .extend(outputs.iter().cloned());
        }
        replacements
    }

    pub(super) fn write_derivation_outputs(
        &self,
        out: &mut Vec<u8>,
        derivation: &nix_compat::derivation::Derivation,
    ) {
        out.push(b'[');
        for (index, (output_name, output)) in derivation.outputs.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.push(b'(');
            Self::write_aterm_field(out, output_name.as_bytes(), true);
            out.push(b',');
            let path = output
                .path
                .as_ref()
                .map(|path| self.store_path_absolute_bytes(path))
                .unwrap_or_default();
            Self::write_aterm_field(out, &path, true);
            out.push(b',');
            let mut mode_and_algo = Vec::new();
            let mut digest = Vec::new();
            if let Some(ca_hash) = output.ca_hash.as_ref() {
                let prefix = match ca_hash {
                    nix_compat::derivation::CAHash::Flat(_) => "",
                    nix_compat::derivation::CAHash::Nar(_) => "r:",
                    nix_compat::derivation::CAHash::Text(_) => "",
                };
                mode_and_algo.extend_from_slice(prefix.as_bytes());
                mode_and_algo.extend_from_slice(ca_hash.hash().algo().to_string().as_bytes());
                Self::write_lower_hex(&mut digest, ca_hash.hash().digest_as_bytes());
            }
            Self::write_aterm_field(out, &mode_and_algo, true);
            out.push(b',');
            Self::write_aterm_field(out, &digest, true);
            out.push(b')');
        }
        out.push(b']');
    }

    pub(super) fn write_derivation_input_paths(
        &self,
        out: &mut Vec<u8>,
        input_derivations: &BTreeMap<nix_compat::store_path::StorePath<String>, BTreeSet<String>>,
    ) {
        out.push(b'[');
        for (index, (drv_path, output_names)) in input_derivations.iter().enumerate() {
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

    pub(super) fn write_derivation_input_hashes(
        out: &mut Vec<u8>,
        input_hashes: &BTreeMap<NixSha256Digest, BTreeSet<String>>,
    ) {
        out.push(b'[');
        for (index, (hash, output_names)) in input_hashes.iter().enumerate() {
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

    pub(super) fn write_derivation_input_sources(
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
}
