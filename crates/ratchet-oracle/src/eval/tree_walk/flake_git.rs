//! Git/flake canonicalization and optional flake-ref attribute extraction.

use super::*;

impl TreeWalk {
    pub(super) fn parse_absolute_path_flake_ref(
        id: IrId,
        span: Span,
        input: &[u8],
        text: &str,
    ) -> Result<FlakeRefAttrs, TreeWalkError> {
        let (without_fragment, fragment) = match text.split_once('#') {
            Some((base, fragment)) => (base, fragment),
            None => (text, ""),
        };
        if !fragment.is_empty() {
            return Err(Self::flake_ref_error(
                id,
                span,
                input,
                "unexpected fragment in flake reference",
            ));
        }
        let (path, query_text) = match without_fragment.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (without_fragment, None),
        };
        if !path.starts_with('/') {
            return Err(Self::flake_ref_error(
                id,
                span,
                input,
                "flake reference is not an absolute path",
            ));
        }
        let query = Self::decode_flake_ref_query(id, span, input, query_text)?;
        let path = Self::percent_decode_flake_ref_component(path)
            .map_err(|message| Self::flake_ref_error(id, span, input, message))?;
        let mut path = String::from_utf8(path)
            .map_err(|source| Self::flake_ref_error(id, span, input, source))?;
        if let Some(dir) = query.get(DIR_ATTR) {
            let dir = std::str::from_utf8(dir)
                .map_err(|source| Self::flake_ref_error(id, span, input, source))?;
            if !dir.is_empty() {
                if !path.ends_with('/') {
                    path.push('/');
                }
                path.push_str(dir);
            }
        }
        let path = Self::canonicalize_flake_ref_path(&path);
        let mut attrs = FlakeRefAttrs::new();
        attrs.insert(
            TYPE_ATTR.to_vec(),
            FlakeRefAttrValue::String(b"path".to_vec()),
        );
        attrs.insert(PATH_ATTR.to_vec(), FlakeRefAttrValue::String(path));
        Ok(attrs)
    }

    pub(super) fn flake_ref_attrs_from_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FlakeRefAttrs, TreeWalkError> {
        let entries = {
            let attrs = self.heap.get_attrs_view(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let mut cloned = Vec::new();
            cloned.try_reserve_exact(attrs.len()).map_err(|_| {
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
            cloned.extend(attrs.iter_lexicographic());
            cloned
        };
        let mut values = FlakeRefAttrs::new();
        for entry in entries {
            let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id,
                        symbol: entry.key,
                    },
                    span,
                )
            })?;
            let key = key.to_vec();
            let value = match entry.value.tag() {
                ValueTag::String => FlakeRefAttrValue::String(self.context_free_string_bytes(
                    id,
                    span,
                    entry.value,
                    "flakeRefToString",
                )?),
                ValueTag::Int => FlakeRefAttrValue::Int(
                    entry
                        .value
                        .as_int()
                        .map(|value| value as u64)
                        .map_err(|source| Self::flake_ref_error(id, span, &key, source))?,
                ),
                ValueTag::Bool => FlakeRefAttrValue::Bool(
                    entry
                        .value
                        .as_bool()
                        .map_err(|source| Self::flake_ref_error(id, span, &key, source))?,
                ),
                actual => {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::FlakeRefAttrType {
                            id,
                            attr: key,
                            actual,
                        },
                        span,
                    ));
                }
            };
            values.insert(key, value);
        }
        Ok(values)
    }

    pub(super) fn flake_ref_attrs_to_string(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let input_type = Self::required_flake_ref_string_attr(id, span, attrs, TYPE_ATTR)?;
        let mut extra_query = BTreeMap::new();
        if let Some(dir) = Self::optional_flake_ref_string_attr(id, span, attrs, DIR_ATTR)? {
            extra_query.insert(DIR_ATTR.to_vec(), dir.to_vec());
        }
        match input_type {
            b"indirect" => self.indirect_flake_ref_to_string(id, span, attrs, extra_query),
            b"github" | b"gitlab" | b"sourcehut" => {
                self.forge_flake_ref_to_string(id, span, attrs, input_type, extra_query)
            }
            b"git" => self.git_flake_ref_to_string(id, span, attrs, extra_query),
            b"path" => Self::path_flake_ref_to_string(id, span, attrs, extra_query),
            b"tarball" | b"file" => self.curl_flake_ref_to_string(id, span, attrs, extra_query),
            _ => Err(Self::flake_ref_error(
                id,
                span,
                input_type,
                "cannot show unsupported flake reference",
            )),
        }
    }

    pub(super) fn indirect_flake_ref_to_string(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                ID_ATTR,
                REF_ATTR,
                REV_ATTR,
                NAR_HASH_ATTR,
                DIR_ATTR,
            ],
        )?;
        let id_attr = Self::required_flake_ref_string_attr(id, span, attrs, ID_ATTR)?;
        if !Self::is_flake_id(id_attr) {
            return Err(Self::flake_ref_error(id, span, id_attr, "invalid flake ID"));
        }
        let mut path = id_attr.to_vec();
        if let Some(reference) = Self::optional_flake_ref_string_attr(id, span, attrs, REF_ATTR)? {
            if !Self::is_flake_ref_name(reference) {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    reference,
                    "invalid indirect ref",
                ));
            }
            path.push(b'/');
            path.extend_from_slice(reference);
        }
        if let Some(rev) = Self::optional_flake_ref_string_attr(id, span, attrs, REV_ATTR)? {
            let rev = self.canonical_flake_ref_rev(id, span, rev)?;
            path.push(b'/');
            path.extend_from_slice(&rev);
        }
        let mut query = BTreeMap::new();
        Self::insert_extra_flake_ref_query(&mut query, extra_query);
        let mut out = b"flake:".to_vec();
        out.extend_from_slice(&Self::percent_encode_flake_ref_path(&path));
        Self::append_flake_ref_query(&mut out, &query);
        Ok(out)
    }

    pub(super) fn forge_flake_ref_to_string(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        input_type: &[u8],
        extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                OWNER_ATTR,
                REPO_ATTR,
                REF_ATTR,
                REV_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                HOST_ATTR,
                b"treeHash",
                DIR_ATTR,
            ],
        )?;
        let owner = Self::required_flake_ref_string_attr(id, span, attrs, OWNER_ATTR)?;
        let repo = Self::required_flake_ref_string_attr(id, span, attrs, REPO_ATTR)?;
        let reference = Self::optional_flake_ref_string_attr(id, span, attrs, REF_ATTR)?;
        let rev = Self::optional_flake_ref_string_attr(id, span, attrs, REV_ATTR)?;
        if reference.is_some() && rev.is_some() {
            return Err(Self::flake_ref_error(
                id,
                span,
                input_type,
                "forge flake reference cannot contain both ref and rev",
            ));
        }
        let mut path = Vec::new();
        path.extend_from_slice(owner);
        path.push(b'/');
        path.extend_from_slice(repo);
        if let Some(reference) = reference {
            if !Self::is_flake_ref_name(reference) {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    reference,
                    "invalid forge ref",
                ));
            }
            path.push(b'/');
            path.extend_from_slice(reference);
        }
        if let Some(rev) = rev {
            let rev = self.canonical_flake_ref_rev(id, span, rev)?;
            path.push(b'/');
            path.extend_from_slice(&rev);
        }

        let mut query = BTreeMap::new();
        if let Some(nar_hash) =
            Self::optional_flake_ref_string_attr(id, span, attrs, NAR_HASH_ATTR)?
        {
            query.insert(
                NAR_HASH_ATTR.to_vec(),
                self.canonical_flake_ref_nar_hash(id, span, nar_hash)?,
            );
        }
        Self::insert_extra_flake_ref_query(&mut query, extra_query);
        let mut out = input_type.to_vec();
        out.push(b':');
        out.extend_from_slice(&Self::percent_encode_flake_ref_path(&path));
        Self::append_flake_ref_query(&mut out, &query);
        Ok(out)
    }

    pub(super) fn git_flake_ref_to_string(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                URL_ATTR,
                REF_ATTR,
                REV_ATTR,
                SHALLOW_ATTR,
                SUBMODULES_ATTR,
                EXPORT_IGNORE_ATTR,
                LAST_MODIFIED_ATTR,
                REV_COUNT_ATTR,
                NAR_HASH_ATTR,
                ALL_REFS_ATTR,
                NAME_ATTR,
                DIRTY_REV_ATTR,
                DIRTY_SHORT_REV_ATTR,
                VERIFY_COMMIT_ATTR,
                KEYTYPE_ATTR,
                PUBLIC_KEY_ATTR,
                PUBLIC_KEYS_ATTR,
                DIR_ATTR,
            ],
        )?;
        let url = Self::required_flake_ref_string_attr(id, span, attrs, URL_ATTR)?;
        let url_text = std::str::from_utf8(url)
            .map_err(|source| Self::flake_ref_error(id, span, url, source))?;
        let url =
            Url::parse(url_text).map_err(|source| Self::flake_ref_error(id, span, url, source))?;
        let mut updates = BTreeMap::new();
        if let Some(rev) = Self::optional_flake_ref_string_attr(id, span, attrs, REV_ATTR)? {
            updates.insert(
                REV_ATTR.to_vec(),
                self.canonical_flake_ref_rev(id, span, rev)?,
            );
        }
        if let Some(reference) = Self::optional_flake_ref_string_attr(id, span, attrs, REF_ATTR)? {
            if Self::is_bad_git_ref(reference) {
                return Err(Self::flake_ref_error(
                    id,
                    span,
                    reference,
                    "invalid Git ref",
                ));
            }
            updates.insert(REF_ATTR.to_vec(), reference.to_vec());
        }
        if let Some(nar_hash) =
            Self::optional_flake_ref_string_attr(id, span, attrs, NAR_HASH_ATTR)?
        {
            updates.insert(
                NAR_HASH_ATTR.to_vec(),
                self.canonical_flake_ref_nar_hash(id, span, nar_hash)?,
            );
        }
        self.insert_git_verified_fetch_query_updates(id, span, attrs, &mut updates)?;
        for attr in [
            SHALLOW_ATTR,
            SUBMODULES_ATTR,
            EXPORT_IGNORE_ATTR,
            VERIFY_COMMIT_ATTR,
        ] {
            if Self::optional_flake_ref_bool_attr(id, span, attrs, attr)? == Some(true) {
                updates.insert(attr.to_vec(), b"1".to_vec());
            }
        }
        Self::flake_ref_url_with_updates(
            id,
            span,
            url.as_str().as_bytes(),
            &url,
            Some(Self::prefixed_git_scheme(url.scheme())?),
            updates,
            extra_query,
        )
    }

    pub(super) fn path_flake_ref_to_string(
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                PATH_ATTR,
                REV_ATTR,
                REV_COUNT_ATTR,
                LAST_MODIFIED_ATTR,
                NAR_HASH_ATTR,
                DIR_ATTR,
            ],
        )?;
        let path = Self::required_flake_ref_string_attr(id, span, attrs, PATH_ATTR)?;
        let mut query = BTreeMap::new();
        for attr in [LAST_MODIFIED_ATTR, NAR_HASH_ATTR, REV_ATTR, REV_COUNT_ATTR] {
            if let Some(value) = attrs.get(attr) {
                query.insert(attr.to_vec(), Self::flake_ref_attr_query_value(value));
            }
        }
        Self::insert_extra_flake_ref_query(&mut query, extra_query);
        let mut out = b"path:".to_vec();
        out.extend_from_slice(&Self::percent_encode_flake_ref_path(path));
        Self::append_flake_ref_query(&mut out, &query);
        Ok(out)
    }

    pub(super) fn curl_flake_ref_to_string(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        Self::ensure_flake_ref_attrs(
            id,
            span,
            attrs,
            &[
                TYPE_ATTR,
                URL_ATTR,
                NAR_HASH_ATTR,
                NAME_ATTR,
                UNPACK_ATTR,
                REV_ATTR,
                REV_COUNT_ATTR,
                LAST_MODIFIED_ATTR,
                DIR_ATTR,
            ],
        )?;
        let url = Self::required_flake_ref_string_attr(id, span, attrs, URL_ATTR)?;
        let url_text = std::str::from_utf8(url)
            .map_err(|source| Self::flake_ref_error(id, span, url, source))?;
        let url =
            Url::parse(url_text).map_err(|source| Self::flake_ref_error(id, span, url, source))?;
        let mut updates = BTreeMap::new();
        if let Some(nar_hash) =
            Self::optional_flake_ref_string_attr(id, span, attrs, NAR_HASH_ATTR)?
        {
            updates.insert(
                NAR_HASH_ATTR.to_vec(),
                self.canonical_flake_ref_nar_hash(id, span, nar_hash)?,
            );
        }
        Self::flake_ref_url_with_updates(
            id,
            span,
            url.as_str().as_bytes(),
            &url,
            None,
            updates,
            extra_query,
        )
    }

    pub(super) fn canonical_flake_ref_rev(
        &self,
        id: IrId,
        span: Span,
        rev: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let digest = self.decode_convert_hash(id, span, rev, Some(HashStringAlgorithm::Sha1))?;
        if digest.algorithm() != HashStringAlgorithm::Sha1 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::HashAlgorithmMismatch {
                    id,
                    hash: rev.to_vec(),
                    expected: b"sha1".to_vec(),
                },
                span,
            ));
        }
        Self::encode_convert_hash_digest(id, span, ConvertHashFormat::Base16, &digest)
    }

    pub(super) fn canonical_flake_ref_nar_hash(
        &self,
        id: IrId,
        span: Span,
        hash: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let Some((algorithm, input_format, payload)) =
            Self::split_convert_hash_typed_input(id, span, hash)?
        else {
            return Err(Self::flake_ref_error(id, span, hash, "hash is not SRI"));
        };
        if !matches!(input_format, ConvertHashInputFormat::Sri) {
            return Err(Self::flake_ref_error(id, span, hash, "hash is not SRI"));
        }
        if algorithm != HashStringAlgorithm::Sha256 {
            return Err(Self::flake_ref_error(
                id,
                span,
                hash,
                "narHash must use SHA-256",
            ));
        }
        let digest = self.decode_sri_hash_payload(id, span, hash, algorithm, payload)?;
        Self::encode_convert_hash_digest(id, span, ConvertHashFormat::Sri, &digest)
    }

    pub(super) fn insert_git_verified_fetch_query_updates(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        updates: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(), TreeWalkError> {
        let keytype = Self::optional_flake_ref_string_attr(id, span, attrs, KEYTYPE_ATTR)?;
        let public_key = Self::optional_flake_ref_string_attr(id, span, attrs, PUBLIC_KEY_ATTR)?;
        let public_keys = Self::optional_flake_ref_string_attr(id, span, attrs, PUBLIC_KEYS_ATTR)?;

        if let Some(public_keys) = public_keys {
            let mut keys = Self::git_public_key_entries_from_json(id, span, public_keys)?;
            if let Some(public_key) = public_key {
                keys.push(GitPublicKeyEntry {
                    keytype: keytype.unwrap_or(b"ssh-ed25519").to_vec(),
                    key: public_key.to_vec(),
                });
            }
            return Self::insert_git_public_key_entries_query_update(id, span, &keys, updates);
        }

        if let Some(public_key) = public_key {
            updates.insert(
                KEYTYPE_ATTR.to_vec(),
                keytype.unwrap_or(b"ssh-ed25519").to_vec(),
            );
            updates.insert(PUBLIC_KEY_ATTR.to_vec(), public_key.to_vec());
        }
        Ok(())
    }

    pub(super) fn git_public_key_entries_from_json(
        id: IrId,
        span: Span,
        public_keys: &[u8],
    ) -> Result<Vec<GitPublicKeyEntry>, TreeWalkError> {
        let value = serde_json::from_slice::<JsonValue>(public_keys).map_err(|source| {
            Self::flake_ref_error(
                id,
                span,
                public_keys,
                format!("invalid publicKeys JSON: {source}"),
            )
        })?;
        let JsonValue::Array(keys) = value else {
            return Err(Self::flake_ref_error(
                id,
                span,
                public_keys,
                "publicKeys must be a JSON array",
            ));
        };
        let mut entries = Vec::new();
        entries.try_reserve_exact(keys.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: keys.len(),
                },
                span,
            )
        })?;
        for key in keys {
            entries.push(GitPublicKeyEntry {
                keytype: Self::git_public_key_json_string(id, span, public_keys, &key, "type")?
                    .as_bytes()
                    .to_vec(),
                key: Self::git_public_key_json_string(id, span, public_keys, &key, "key")?
                    .as_bytes()
                    .to_vec(),
            });
        }
        Ok(entries)
    }

    pub(super) fn insert_git_public_key_entries_query_update(
        id: IrId,
        span: Span,
        keys: &[GitPublicKeyEntry],
        updates: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(), TreeWalkError> {
        if keys.is_empty() {
            return Ok(());
        }
        if keys.len() == 1 {
            let key = &keys[0];
            updates.insert(KEYTYPE_ATTR.to_vec(), key.keytype.clone());
            updates.insert(PUBLIC_KEY_ATTR.to_vec(), key.key.clone());
            return Ok(());
        }
        let entries = keys
            .iter()
            .map(|key| -> Result<JsonValue, TreeWalkError> {
                let public_key = std::str::from_utf8(&key.key)
                    .map_err(|source| Self::fetch_tree_error(id, span, PUBLIC_KEY_ATTR, source))?;
                let keytype = std::str::from_utf8(&key.keytype)
                    .map_err(|source| Self::fetch_tree_error(id, span, KEYTYPE_ATTR, source))?;
                let mut entry = serde_json::Map::new();
                entry.insert("key".to_owned(), JsonValue::String(public_key.to_owned()));
                entry.insert("type".to_owned(), JsonValue::String(keytype.to_owned()));
                Ok(JsonValue::Object(entry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let json = serde_json::to_vec(&JsonValue::Array(entries)).map_err(|source| {
            Self::flake_ref_error(
                id,
                span,
                PUBLIC_KEYS_ATTR,
                format!("invalid publicKeys JSON: {source}"),
            )
        })?;
        updates.insert(PUBLIC_KEYS_ATTR.to_vec(), json);
        Ok(())
    }

    pub(super) fn git_public_key_json_string<'a>(
        id: IrId,
        span: Span,
        public_keys: &[u8],
        value: &'a JsonValue,
        name: &str,
    ) -> Result<&'a str, TreeWalkError> {
        value.get(name).and_then(JsonValue::as_str).ok_or_else(|| {
            Self::flake_ref_error(
                id,
                span,
                public_keys,
                format!("publicKeys entries must contain string '{name}' fields"),
            )
        })
    }

    pub(super) fn alloc_flake_ref_attrs(
        &mut self,
        id: IrId,
        span: Span,
        attrs: FlakeRefAttrs,
    ) -> Result<Value, TreeWalkError> {
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
        for (key, value) in attrs {
            let symbol = self.intern_symbol_for_eval(&key).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SymbolIntern {
                        id,
                        source: source.kind().clone(),
                    },
                    span,
                )
            })?;
            let value = match value {
                FlakeRefAttrValue::String(value) => self.alloc_static_string(id, span, &value)?,
                FlakeRefAttrValue::Int(value) => {
                    let value = i64::try_from(value).map_err(|_| {
                        Self::flake_ref_error(
                            id,
                            span,
                            &key,
                            "flake reference integer does not fit in Nix int",
                        )
                    })?;
                    self.runtime_int_value(id, span, value)?
                }
                FlakeRefAttrValue::Bool(value) => Value::bool(value),
            };
            entries.push(AttrEntry::new(symbol, value));
        }
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn ensure_flake_ref_attrs(
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        allowed: &[&[u8]],
    ) -> Result<(), TreeWalkError> {
        for key in attrs.keys() {
            if !allowed.contains(&key.as_slice()) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedFlakeRefAttr {
                        id,
                        attr: key.clone(),
                    },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn required_flake_ref_string_attr<'a>(
        id: IrId,
        span: Span,
        attrs: &'a FlakeRefAttrs,
        name: &[u8],
    ) -> Result<&'a [u8], TreeWalkError> {
        Self::optional_flake_ref_string_attr(id, span, attrs, name)?.ok_or_else(|| {
            Self::flake_ref_error(
                id,
                span,
                name,
                format!(
                    "input attribute '{}' is missing",
                    String::from_utf8_lossy(name)
                ),
            )
        })
    }

    pub(super) fn optional_flake_ref_string_attr<'a>(
        id: IrId,
        span: Span,
        attrs: &'a FlakeRefAttrs,
        name: &[u8],
    ) -> Result<Option<&'a [u8]>, TreeWalkError> {
        match attrs.get(name) {
            Some(FlakeRefAttrValue::String(value)) => Ok(Some(value)),
            Some(_) => Err(TreeWalkError::new(
                TreeWalkErrorKind::FlakeRef {
                    id,
                    input: name.to_vec(),
                    message: "flake reference attribute is not a string".to_owned(),
                },
                span,
            )),
            None => Ok(None),
        }
    }

    pub(super) fn optional_flake_ref_bool_attr(
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        name: &[u8],
    ) -> Result<Option<bool>, TreeWalkError> {
        match attrs.get(name) {
            Some(FlakeRefAttrValue::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(TreeWalkError::new(
                TreeWalkErrorKind::FlakeRef {
                    id,
                    input: name.to_vec(),
                    message: "flake reference attribute has the wrong type".to_owned(),
                },
                span,
            )),
            None => Ok(None),
        }
    }

    pub(super) fn optional_flake_ref_i64_attr(
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        name: &[u8],
    ) -> Result<Option<i64>, TreeWalkError> {
        let Some(value) = Self::optional_flake_ref_u64_attr(id, span, attrs, name)? else {
            return Ok(None);
        };
        i64::try_from(value).map(Some).map_err(|_| {
            Self::flake_ref_error(
                id,
                span,
                name,
                "flake reference integer attribute does not fit in Nix int",
            )
        })
    }

    pub(super) fn optional_flake_ref_usize_attr(
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        name: &[u8],
    ) -> Result<Option<usize>, TreeWalkError> {
        let Some(value) = Self::optional_flake_ref_u64_attr(id, span, attrs, name)? else {
            return Ok(None);
        };
        usize::try_from(value).map(Some).map_err(|_| {
            Self::flake_ref_error(
                id,
                span,
                name,
                "flake reference integer attribute does not fit in usize",
            )
        })
    }

    pub(super) fn optional_flake_ref_u64_attr(
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
        name: &[u8],
    ) -> Result<Option<u64>, TreeWalkError> {
        match attrs.get(name) {
            Some(FlakeRefAttrValue::Int(value)) => Ok(Some(*value)),
            Some(_) => Err(TreeWalkError::new(
                TreeWalkErrorKind::FlakeRef {
                    id,
                    input: name.to_vec(),
                    message: "flake reference attribute has the wrong type".to_owned(),
                },
                span,
            )),
            None => Ok(None),
        }
    }

    pub(super) fn optional_flake_ref_nar_hash_attr(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
    ) -> Result<Option<NixSha256Digest>, TreeWalkError> {
        let Some(hash) = Self::optional_flake_ref_string_attr(id, span, attrs, NAR_HASH_ATTR)?
        else {
            return Ok(None);
        };
        self.decode_fetch_tree_nar_hash(id, span, hash).map(Some)
    }
}
