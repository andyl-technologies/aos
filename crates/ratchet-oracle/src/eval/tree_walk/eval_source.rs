//! Source-path builtins and their serialization/cloning helpers.

use super::*;

impl TreeWalk {
    pub(super) fn derivation_scalar_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        match value.tag() {
            ValueTag::String => self.clone_string_value(value_id, value_span, value),
            ValueTag::Path => self.source_path_store_string(value_id, value_span, value),
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
            ValueTag::Attrs => {
                self.derivation_attrs_to_string_value(id, span, value_id, value_span, value)
            }
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

    pub(super) fn attrs_to_string_value(
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
            return self.coerce_to_string_value(id, span, attrs_id, attrs_span, value);
        }

        if let Some(out_path) =
            self.attr_value_by_name(attrs_id, attrs_value, OUT_PATH_ATTR, attrs_span)?
        {
            let value = self.force_value(attrs_id, attrs_span, out_path)?;
            return self.coerce_to_string_value(id, span, attrs_id, attrs_span, value);
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

    pub(super) fn derivation_attrs_to_string_value(
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
            return self.derivation_to_string_value(id, span, attrs_id, attrs_span, value);
        }

        if let Some(out_path) =
            self.attr_value_by_name(attrs_id, attrs_value, OUT_PATH_ATTR, attrs_span)?
        {
            let value = self.force_value(attrs_id, attrs_span, out_path)?;
            return self.derivation_to_string_value(id, span, attrs_id, attrs_span, value);
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

    pub(super) fn clone_string_value(
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

    pub(super) fn clone_path_value(
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

    pub(super) fn source_path_store_string(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let path = self
            .heap
            .get_path(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let bytes = path_without_trailing_path_markers(path.bytes()).to_vec();
        self.source_path_store_string_from_default_name(id, span, &bytes, true, None, None)
    }

    pub(super) fn source_path_store_string_from_default_name(
        &mut self,
        id: IrId,
        span: Span,
        bytes: &[u8],
        recursive: bool,
        expected_sha256: Option<NixSha256Digest>,
        filter: Option<&SourcePathFilter>,
    ) -> Result<NixString, TreeWalkError> {
        if !Path::new(OsStr::from_bytes(bytes)).is_absolute() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::PathNotAbsolute {
                    id,
                    path: bytes.to_vec(),
                },
                span,
            ));
        }
        self.check_filesystem_path_access(id, span, bytes)?;
        let name = self.default_source_path_name(id, span, bytes)?;
        let name = Self::source_path_store_name(id, span, bytes, &name)?;
        self.source_path_store_string_from_bytes(
            id,
            span,
            bytes,
            name,
            recursive,
            expected_sha256,
            filter,
        )
    }

    pub(super) fn source_path_store_string_from_bytes(
        &mut self,
        id: IrId,
        span: Span,
        bytes: &[u8],
        name: &str,
        recursive: bool,
        expected_sha256: Option<NixSha256Digest>,
        filter: Option<&SourcePathFilter>,
    ) -> Result<NixString, TreeWalkError> {
        let source_path = Path::new(OsStr::from_bytes(bytes));
        let digest = if recursive {
            self.source_path_nar_sha256(id, span, source_path, filter)?
        } else {
            self.source_path_flat_sha256(id, span, source_path)?
        };
        if let Some(expected) = expected_sha256
            && expected != digest
        {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::SourcePathHashMismatch {
                    id,
                    path: bytes.to_vec(),
                    expected: expected.as_bytes().to_vec(),
                    actual: digest.as_bytes().to_vec(),
                },
                span,
            ));
        }
        let store_path = if recursive {
            self.store_path_bytes_from_fingerprint_parts(id, span, bytes, b"source", name, digest)?
        } else {
            let fixed_digest = Self::flat_source_fixed_output_digest(id, span, digest)?;
            self.store_path_bytes_from_fingerprint_parts(
                id,
                span,
                bytes,
                b"output:out",
                name,
                fixed_digest,
            )?
        };
        let context =
            StringContext::singleton(ContextElement::opaque_path(store_path.clone()).map_err(
                |source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span),
            )?)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(NixString::new(store_path, context))
    }

    pub(super) fn source_path_argument_bytes(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let value = self.force_value(id, span, value)?;
        let path = self.coerce_to_path_string(id, span, value)?;
        self.validate_ifd_path_context(id, span, &path, "path")?;
        let bytes =
            Self::copy_bytes_for_node(id, span, path_without_trailing_path_markers(path.bytes()))?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        self.realize_import_from_derivation(id, span, &path, "path")?;
        self.check_filesystem_path_access(id, span, &bytes)?;
        Ok(bytes)
    }

    pub(super) fn default_source_path_name(
        &self,
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let path = Path::new(OsStr::from_bytes(bytes));
        let Some(name) = path.file_name().map(OsStrExt::as_bytes) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::SourcePathStoreName {
                    id,
                    path: bytes.to_vec(),
                    message: "source path has no store name component".to_owned(),
                },
                span,
            ));
        };
        Self::copy_bytes_for_node(id, span, name)
    }

    pub(super) fn source_path_store_name<'a>(
        id: IrId,
        span: Span,
        source_path: &[u8],
        name: &'a [u8],
    ) -> Result<&'a str, TreeWalkError> {
        nix_compat::store_path::validate_name(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SourcePathStoreName {
                    id,
                    path: source_path.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })
    }

    pub(super) fn source_path_nar_sha256(
        &mut self,
        id: IrId,
        span: Span,
        path: &Path,
        filter: Option<&SourcePathFilter>,
    ) -> Result<NixSha256Digest, TreeWalkError> {
        // Stream the NAR encoding straight into the hasher instead of
        // buffering the whole archive: source trees can be tens of megabytes
        // and the intermediate `Vec` was pure allocator and memcpy traffic.
        let mut hasher = Sha256StreamHasher::new();
        {
            let node = nix_compat::nar::writer::open(&mut hasher)
                .map_err(|source| Self::source_path_archive_error(id, span, path, source))?;
            self.write_source_path_nar_node(id, span, path, node, true, filter)?;
        }
        Ok(NixSha256Digest::from_bytes(hasher.finish()))
    }

    pub(super) fn source_path_flat_sha256(
        &self,
        id: IrId,
        span: Span,
        path: &Path,
    ) -> Result<NixSha256Digest, TreeWalkError> {
        let contents = fs::read(path)
            .map_err(|source| Self::source_path_archive_error(id, span, path, source))?;
        Ok(NixSha256Digest::from_bytes(Self::sha256_array(&contents)))
    }

    pub(super) fn write_source_path_nar_node<W: io::Write>(
        &mut self,
        id: IrId,
        span: Span,
        path: &Path,
        node: nix_compat::nar::writer::Node<'_, W>,
        follow_root_symlink: bool,
        filter: Option<&SourcePathFilter>,
    ) -> Result<(), TreeWalkError> {
        let metadata = if follow_root_symlink {
            fs::metadata(path)
        } else {
            fs::symlink_metadata(path)
        }
        .map_err(|source| Self::source_path_archive_error(id, span, path, source))?;
        let file_type = metadata.file_type();
        if file_type.is_file() {
            let file = fs::File::open(path)
                .map_err(|source| Self::source_path_archive_error(id, span, path, source))?;
            let mut reader = io::BufReader::new(file);
            return node
                .file(
                    metadata.permissions().mode() & 0o111 != 0,
                    metadata.len(),
                    &mut reader,
                )
                .map_err(|source| Self::source_path_archive_error(id, span, path, source));
        }
        if file_type.is_symlink() {
            let target = fs::read_link(path)
                .map_err(|source| Self::source_path_archive_error(id, span, path, source))?;
            return node
                .symlink(target.as_os_str().as_bytes())
                .map_err(|source| Self::source_path_archive_error(id, span, path, source));
        }
        if file_type.is_dir() {
            let mut entries = Vec::new();
            let read_dir = fs::read_dir(path)
                .map_err(|source| Self::source_path_archive_error(id, span, path, source))?;
            for entry in read_dir {
                let entry = entry
                    .map_err(|source| Self::source_path_archive_error(id, span, path, source))?;
                let child_path = entry.path();
                let child_type = fs::symlink_metadata(&child_path)
                    .map_err(|source| {
                        Self::source_path_archive_error(id, span, &child_path, source)
                    })?
                    .file_type();
                entries.push((
                    entry.file_name().as_bytes().to_vec(),
                    child_path,
                    child_type,
                ));
            }
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

            let mut directory = node
                .directory()
                .map_err(|source| Self::source_path_archive_error(id, span, path, source))?;
            for (name, child_path, child_type) in entries {
                if !self.source_path_filter_includes(id, span, filter, &child_path, child_type)? {
                    continue;
                }
                let child = directory.entry(&name).map_err(|source| {
                    Self::source_path_archive_error(id, span, &child_path, source)
                })?;
                self.write_source_path_nar_node(id, span, &child_path, child, false, filter)?;
            }
            return directory
                .close()
                .map_err(|source| Self::source_path_archive_error(id, span, path, source));
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::UnsupportedSourcePathType {
                id,
                path: path.as_os_str().as_bytes().to_vec(),
            },
            span,
        ))
    }

    pub(super) fn source_path_filter_includes(
        &mut self,
        id: IrId,
        span: Span,
        filter: Option<&SourcePathFilter>,
        path: &Path,
        file_type: fs::FileType,
    ) -> Result<bool, TreeWalkError> {
        let Some(filter) = filter else {
            return Ok(true);
        };
        let path_value = self.alloc_static_string(id, span, path.as_os_str().as_bytes())?;
        let type_value = self.alloc_static_string(id, span, file_type_name(file_type))?;
        let value = self.apply_lambda_value_2(
            id,
            span,
            filter.id,
            filter.function,
            filter.span,
            id,
            span,
            path_value,
            id,
            span,
            type_value,
        )?;
        let value = self.force_value(id, span, value)?;
        self.expect_bool(id, value, span)
    }

    pub(super) fn flat_source_fixed_output_digest(
        id: IrId,
        span: Span,
        digest: NixSha256Digest,
    ) -> Result<NixSha256Digest, TreeWalkError> {
        let digest = Self::lower_hex_bytes(id, span, digest.as_bytes())?;
        let len = b"fixed:out:sha256:"
            .len()
            .checked_add(digest.len())
            .and_then(|len| len.checked_add(1))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        let mut fingerprint = Vec::new();
        fingerprint.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        fingerprint.extend_from_slice(b"fixed:out:sha256:");
        fingerprint.extend_from_slice(&digest);
        fingerprint.push(b':');
        Ok(Self::nix_sha256_digest(&fingerprint))
    }

    pub(super) fn store_path_bytes_from_fingerprint_parts(
        &self,
        id: IrId,
        span: Span,
        source_path: &[u8],
        fingerprint_type: &[u8],
        name: &str,
        inner_digest: NixSha256Digest,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let digest = Self::lower_hex_bytes(id, span, inner_digest.as_bytes())?;
        let store_dir = self.options.store_dir();
        let len = fingerprint_type
            .len()
            .checked_add(b":sha256:".len())
            .and_then(|len| len.checked_add(digest.len()))
            .and_then(|len| len.checked_add(1))
            .and_then(|len| len.checked_add(store_dir.len()))
            .and_then(|len| len.checked_add(1))
            .and_then(|len| len.checked_add(name.len()))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        let mut fingerprint = Vec::new();
        fingerprint.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        fingerprint.extend_from_slice(fingerprint_type);
        fingerprint.extend_from_slice(b":sha256:");
        fingerprint.extend_from_slice(&digest);
        fingerprint.push(b':');
        fingerprint.extend_from_slice(store_dir);
        fingerprint.push(b':');
        fingerprint.extend_from_slice(name.as_bytes());

        let fingerprint_hash = Self::sha256_array(&fingerprint);
        let digest = nix_compat::store_path::compress_hash::<{ nix_compat::store_path::DIGEST_SIZE }>(
            &fingerprint_hash,
        );
        let store_path =
            nix_compat::store_path::StorePath::<&str>::from_name_and_digest_fixed(name, digest)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::SourcePathStoreName {
                            id,
                            path: source_path.to_vec(),
                            message: source.to_string(),
                        },
                        span,
                    )
                })?
                .to_string();
        let needs_slash = !store_dir.ends_with(b"/");
        let len = store_dir
            .len()
            .checked_add(usize::from(needs_slash))
            .and_then(|len| len.checked_add(store_path.len()))
            .ok_or_else(|| {
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
        bytes.extend_from_slice(store_dir);
        if needs_slash {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(store_path.as_bytes());
        Ok(bytes)
    }

    pub(super) fn source_path_archive_error(
        id: IrId,
        span: Span,
        path: &Path,
        source: impl std::fmt::Display,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::SourcePathArchive {
                id,
                path: path.as_os_str().as_bytes().to_vec(),
                message: source.to_string(),
            },
            span,
        )
    }

    pub(super) fn to_string_float_bytes(value: f64) -> Vec<u8> {
        if value.is_nan() {
            return b"nan".to_vec();
        }
        let value = if value == 0.0 { 0.0 } else { value };
        format!("{value:.6}").into_bytes()
    }

    pub(super) fn eval_to_json_primop(
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
        self.alloc_tree_walk_string(id, span, NixString::new(bytes, context))
    }

    pub(super) fn write_json_value(
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
            ValueTag::Path => {
                self.write_json_path_value(id, span, value_id, value_span, value, out, context)
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

    pub(super) fn write_json_float(
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

    pub(super) fn normalize_json_float_exponent(bytes: &mut Vec<u8>) {
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

    pub(super) fn write_json_string_value(
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

    pub(super) fn write_json_path_value(
        &mut self,
        id: IrId,
        span: Span,
        path_id: IrId,
        path_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        context: &mut StringContext,
    ) -> Result<(), TreeWalkError> {
        let path = self.source_path_store_string(path_id, path_span, value)?;
        Self::write_json_string_bytes(id, span, path.bytes(), out)?;
        *context = context
            .union(path.context())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(())
    }

    pub(super) fn write_json_string_bytes(
        id: IrId,
        span: Span,
        bytes: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        std::str::from_utf8(bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::JsonInvalidUtf8 {
                    id,
                    bytes: bytes.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })?;
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

    pub(super) fn write_json_list(
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

    pub(super) fn write_json_attrs(
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
}

/// An [`io::Write`] adapter that feeds every written byte into a streaming
/// SHA-256 context.
///
/// Used to hash NAR encodings of source trees without materializing the
/// archive bytes in memory.
struct Sha256StreamHasher {
    context: ring::digest::Context,
}

impl Sha256StreamHasher {
    /// Creates a hasher with an empty SHA-256 state.
    fn new() -> Self {
        Self {
            context: ring::digest::Context::new(&ring::digest::SHA256),
        }
    }

    /// Consumes the hasher and returns the SHA-256 digest of all bytes
    /// written so far.
    fn finish(self) -> [u8; 32] {
        let digest = self.context.finish();
        let mut out = [0_u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
}

impl io::Write for Sha256StreamHasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.context.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
