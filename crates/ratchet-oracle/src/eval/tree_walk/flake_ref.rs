//! Flake-ref percent-encoding, classification, and tarball unpacking.

use super::*;

impl TreeWalk {
    pub(super) fn fetch_tree_git_flake_ref_verified_fetch_query(
        &self,
        id: IrId,
        span: Span,
        attrs: &FlakeRefAttrs,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, TreeWalkError> {
        let mut query = BTreeMap::new();
        self.insert_git_verified_fetch_query_updates(id, span, attrs, &mut query)?;
        if Self::optional_flake_ref_bool_attr(id, span, attrs, VERIFY_COMMIT_ATTR)? == Some(true) {
            return Err(Self::fetch_tree_verified_fetches_unsupported(
                id,
                span,
                VERIFY_COMMIT_ATTR,
            ));
        }
        Ok(query)
    }

    pub(super) fn flake_ref_attr_query_value(value: &FlakeRefAttrValue) -> Vec<u8> {
        match value {
            FlakeRefAttrValue::String(value) => value.clone(),
            FlakeRefAttrValue::Int(value) => value.to_string().into_bytes(),
            FlakeRefAttrValue::Bool(value) => {
                if *value {
                    b"1".to_vec()
                } else {
                    b"0".to_vec()
                }
            }
        }
    }

    pub(super) fn flake_ref_url_with_updates(
        id: IrId,
        span: Span,
        input: &[u8],
        url: &Url,
        scheme: Option<Vec<u8>>,
        updates: BTreeMap<Vec<u8>, Vec<u8>>,
        extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let query = Self::decode_flake_ref_query(id, span, input, url.query())?;
        let scheme = match scheme {
            Some(scheme) => Some(
                std::str::from_utf8(&scheme)
                    .map_err(|source| Self::flake_ref_error(id, span, input, source))?
                    .to_owned(),
            ),
            None => None,
        };
        let mut query = query;
        for (name, value) in updates {
            query.insert(name, value);
        }
        Self::insert_extra_flake_ref_query(&mut query, extra_query);
        Self::flake_ref_url_with_scheme_and_query(
            id,
            span,
            input,
            url,
            scheme.as_deref(),
            query,
            BTreeMap::new(),
        )
    }

    pub(super) fn flake_ref_url_with_scheme_and_query(
        id: IrId,
        span: Span,
        input: &[u8],
        url: &Url,
        scheme: Option<&str>,
        mut query: BTreeMap<Vec<u8>, Vec<u8>>,
        updates: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        for (name, value) in updates {
            query.insert(name, value);
        }
        let mut url = url.clone();
        let fragment = url.fragment().map(|fragment| fragment.as_bytes().to_vec());
        url.set_query(None);
        url.set_fragment(None);
        let mut out = url.as_str().as_bytes().to_vec();
        if let Some(scheme) = scheme {
            let colon = out.iter().position(|byte| *byte == b':').ok_or_else(|| {
                Self::flake_ref_error(id, span, input, "URL is missing a scheme separator")
            })?;
            out.splice(0..colon, scheme.as_bytes().iter().copied());
        }
        Self::append_flake_ref_query(&mut out, &query);
        if let Some(fragment) = fragment {
            out.push(b'#');
            out.extend_from_slice(&Self::percent_encode_flake_ref_path(&fragment));
        }
        Ok(out)
    }

    pub(super) fn insert_extra_flake_ref_query(
        query: &mut BTreeMap<Vec<u8>, Vec<u8>>,
        extra_query: BTreeMap<Vec<u8>, Vec<u8>>,
    ) {
        for (name, value) in extra_query {
            query.entry(name).or_insert(value);
        }
    }

    pub(super) fn append_flake_ref_query(out: &mut Vec<u8>, query: &BTreeMap<Vec<u8>, Vec<u8>>) {
        if query.is_empty() {
            return;
        }
        out.push(b'?');
        let mut first = true;
        for (name, value) in query {
            if first {
                first = false;
            } else {
                out.push(b'&');
            }
            out.extend_from_slice(&Self::percent_encode_flake_ref_query(name));
            out.push(b'=');
            out.extend_from_slice(&Self::percent_encode_flake_ref_query(value));
        }
    }

    pub(super) fn decode_flake_ref_query(
        id: IrId,
        span: Span,
        input: &[u8],
        query: Option<&str>,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, TreeWalkError> {
        let mut values = BTreeMap::new();
        let Some(query) = query else {
            return Ok(values);
        };
        for piece in query.split('&') {
            let Some((name, value)) = piece.split_once('=') else {
                continue;
            };
            let name = name.as_bytes().to_vec();
            let value = Self::percent_decode_flake_ref_component(value)
                .map_err(|message| Self::flake_ref_error(id, span, input, message))?;
            values.entry(name).or_insert(value);
        }
        Ok(values)
    }

    pub(super) fn percent_decode_flake_ref_component(input: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let bytes = input.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let Some(first) = bytes.get(index + 1).copied() else {
                    return Err(format!("invalid URI parameter '{input}'"));
                };
                let Some(second) = bytes.get(index + 2).copied() else {
                    return Err(format!("invalid URI parameter '{input}'"));
                };
                let Some(high) = Self::flake_ref_hex_digit(first) else {
                    return Err(format!("invalid URI parameter '{input}'"));
                };
                let Some(low) = Self::flake_ref_hex_digit(second) else {
                    return Err(format!("invalid URI parameter '{input}'"));
                };
                out.push((high << 4) | low);
                index += 3;
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        }
        Ok(out)
    }

    pub(super) fn percent_encode_flake_ref_path(input: &[u8]) -> Vec<u8> {
        Self::percent_encode_flake_ref(input, b":@/")
    }

    pub(super) fn percent_encode_flake_ref_query(input: &[u8]) -> Vec<u8> {
        Self::percent_encode_flake_ref(input, b":@/?")
    }

    pub(super) fn percent_encode_flake_ref(input: &[u8], keep: &[u8]) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = Vec::with_capacity(input.len());
        for byte in input {
            if byte.is_ascii_alphanumeric()
                || matches!(*byte, b'-' | b'.' | b'_' | b'~')
                || keep.contains(byte)
            {
                out.push(*byte);
            } else {
                out.push(b'%');
                out.push(HEX[(byte >> 4) as usize]);
                out.push(HEX[(byte & 0x0f) as usize]);
            }
        }
        out
    }

    pub(super) fn flake_ref_hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    pub(super) fn parse_flake_ref_u64(
        id: IrId,
        span: Span,
        input: &[u8],
        value: &[u8],
        name: &[u8],
    ) -> Result<u64, TreeWalkError> {
        let text = std::str::from_utf8(value)
            .map_err(|source| Self::flake_ref_error(id, span, input, source))?;
        text.parse::<u64>().map_err(|source| {
            Self::flake_ref_error(
                id,
                span,
                input,
                format!(
                    "flake reference parameter '{}' is not an unsigned integer: {source}",
                    String::from_utf8_lossy(name)
                ),
            )
        })
    }

    pub(super) fn curl_flake_ref_url_type(url: &Url) -> Option<&'static [u8]> {
        let scheme = url.scheme();
        let (application, transport) = match scheme.split_once('+') {
            Some((application, transport)) => (Some(application), transport),
            None => (None, scheme),
        };
        if !matches!(transport, "file" | "http" | "https") {
            return None;
        }
        match application {
            None | Some("tarball") => Some(b"tarball"),
            Some("file") => Some(b"file"),
            Some(_) => None,
        }
    }

    pub(super) fn flake_ref_transport_scheme(scheme: &str) -> Option<&str> {
        scheme.split_once('+').map(|(_, transport)| transport)
    }

    pub(super) fn prefixed_git_scheme(scheme: &str) -> Result<Vec<u8>, TreeWalkError> {
        if scheme == "git" {
            return Ok(b"git".to_vec());
        }
        let mut prefixed = b"git+".to_vec();
        prefixed.extend_from_slice(scheme.as_bytes());
        Ok(prefixed)
    }

    pub(super) fn canonicalize_flake_ref_path(path: &str) -> Vec<u8> {
        let mut parts = Vec::new();
        for component in Path::new(path).components() {
            match component {
                Component::RootDir => {}
                Component::CurDir => {}
                Component::ParentDir => {
                    parts.pop();
                }
                Component::Normal(component) => parts.push(component.as_bytes().to_vec()),
                Component::Prefix(_) => {}
            }
        }
        let mut out = b"/".to_vec();
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                out.push(b'/');
            }
            out.extend_from_slice(part);
        }
        out
    }

    pub(super) fn split_ref_and_rev(value: &str) -> Option<(&str, &str)> {
        let (reference, rev) = value.rsplit_once('/')?;
        (!reference.is_empty()
            && Self::is_flake_ref_name(reference.as_bytes())
            && Self::is_git_rev(rev.as_bytes()))
        .then_some((reference, rev))
    }

    pub(super) fn is_flake_id(value: &[u8]) -> bool {
        let Some((first, rest)) = value.split_first() else {
            return false;
        };
        first.is_ascii_alphabetic()
            && rest
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    }

    pub(super) fn is_flake_ref_name(value: &[u8]) -> bool {
        let Some((first, rest)) = value.split_first() else {
            return false;
        };
        (first.is_ascii_alphanumeric() || *first == b'@')
            && rest.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(*byte, b'_' | b'.' | b'/' | b'@' | b'+' | b'-')
            })
    }

    pub(super) fn is_git_rev(value: &[u8]) -> bool {
        value.len() == 40 && value.iter().all(|byte| byte.is_ascii_hexdigit())
    }

    pub(super) fn is_bad_git_ref(value: &[u8]) -> bool {
        value.is_empty()
            || value == b"@"
            || value.starts_with(b".")
            || value.starts_with(b"/")
            || value.ends_with(b".")
            || value.ends_with(b"/")
            || value.ends_with(b".lock")
            || value
                .windows(2)
                .any(|window| matches!(window, b"//" | b".." | b"/."))
            || value.windows(6).any(|window| window == b".lock/")
            || value.windows(2).any(|window| window == b"@{")
            || value.iter().any(|byte| {
                byte.is_ascii_control()
                    || byte.is_ascii_whitespace()
                    || matches!(*byte, b':' | b'?' | b'^' | b'~' | b'[' | b'\\' | b'*')
            })
    }

    pub(super) fn is_forge_host(value: &[u8]) -> bool {
        !value.is_empty()
            && value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-'))
    }

    pub(super) fn flake_ref_error(
        id: IrId,
        span: Span,
        input: &[u8],
        source: impl std::fmt::Display,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::FlakeRef {
                id,
                input: input.to_vec(),
                message: source.to_string(),
            },
            span,
        )
    }

    pub(super) fn eval_fetch_tarball_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_demanded_value(argument, argument_span, value)?;
        let args = self.fetch_tarball_arguments(argument, argument_span, value)?;
        if self.options.eval_mode() == EvalMode::Pure && args.expected_sha256.is_none() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTarballHashRequired {
                    id: argument,
                    url: args.url,
                    mode: EvalMode::Pure,
                },
                argument_span,
            ));
        }

        let parsed = Self::parse_fetchurl_url(argument, argument_span, &args.url)?;
        self.check_fetch_tarball_access(argument, argument_span, &args.url, &parsed)?;

        let expected_path = if let Some(expected) = args.expected_sha256 {
            let path = self.fetch_tarball_store_path_from_digest(
                argument,
                argument_span,
                &args.url,
                &args.name,
                expected,
            )?;
            if self.fetch_tarball_can_reuse_store_path(
                argument,
                argument_span,
                &args.url,
                &parsed,
                &path,
                expected,
            )? {
                return self.alloc_fetcher_result_path_value(id, span, path);
            }
            Some(path)
        } else {
            None
        };

        let contents = self.fetchurl_bytes(argument, argument_span, &args.url, &parsed)?;
        let temp_dir = Self::fetch_tarball_temp_dir(argument, argument_span, &args.url)?;
        let unpack_dir = temp_dir.join("unpacked");
        fs::create_dir(&unpack_dir).map_err(|source| {
            Self::fetch_tarball_error(argument, argument_span, &args.url, source)
        })?;
        let unpack_result = Self::unpack_fetch_tarball_archive(
            argument,
            argument_span,
            &args.url,
            &parsed,
            &contents,
            &unpack_dir,
        )
        .and_then(|()| {
            Self::fetch_tarball_unpacked_root(argument, argument_span, &args.url, &unpack_dir)
        });
        let unpacked_root = match unpack_result {
            Ok(root) => root,
            Err(error) => {
                let _ = fs::remove_dir_all(&temp_dir);
                return Err(error);
            }
        };

        let digest =
            match self.source_path_nar_sha256(argument, argument_span, &unpacked_root, None) {
                Ok(digest) => digest,
                Err(error) => {
                    let _ = fs::remove_dir_all(&temp_dir);
                    return Err(error);
                }
            };
        if let Some(expected) = args.expected_sha256
            && expected != digest
        {
            let _ = fs::remove_dir_all(&temp_dir);
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTarballHashMismatch {
                    id: argument,
                    url: args.url,
                    expected: expected.as_bytes().to_vec(),
                    actual: digest.as_bytes().to_vec(),
                },
                argument_span,
            ));
        }

        let path = match expected_path {
            Some(path) => path,
            None => self.fetch_tarball_store_path_from_digest(
                argument,
                argument_span,
                &args.url,
                &args.name,
                digest,
            )?,
        };
        let materialize_result = self.materialize_fetch_tarball_store_path(
            argument,
            argument_span,
            &args.url,
            &unpacked_root,
            &path,
            digest,
        );
        let _ = fs::remove_dir_all(&temp_dir);
        materialize_result?;
        self.alloc_fetcher_result_path_value(id, span, path)
    }

    pub(super) fn fetch_tarball_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchTarballArguments, TreeWalkError> {
        if value.tag() == ValueTag::String {
            let url = self.context_free_string_bytes(id, span, value, "fetchTarball")?;
            let name = Self::fetch_tarball_store_name(id, span, &url, b"source")?.to_owned();
            return Ok(FetchTarballArguments {
                url,
                name,
                expected_sha256: None,
            });
        }
        if value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "set or string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        self.validate_fetch_tarball_attrs(id, span, value)?;

        let url_value = self.required_attr_value_by_name(id, value, URL_ATTR, span)?;
        let url_value = self.force_value(id, span, url_value)?;
        let url = self.context_free_string_bytes(id, span, url_value, "fetchTarball")?;

        let name = if let Some(name_value) = self.attr_value_by_name(id, value, NAME_ATTR, span)? {
            let name_value = self.force_value(id, span, name_value)?;
            self.context_free_string_bytes(id, span, name_value, "fetchTarball")?
        } else {
            b"source".to_vec()
        };
        let name = Self::fetch_tarball_store_name(id, span, &url, &name)?.to_owned();

        let expected_sha256 = if let Some(hash_value) =
            self.attr_value_by_name(id, value, SHA256_ATTR, span)?
        {
            let hash_value = self.force_value(id, span, hash_value)?;
            let hash = self.context_free_string_bytes(id, span, hash_value, "fetchTarball")?;
            if hash.is_empty() {
                self.emit_warning_output(id, span, EMPTY_FETCHURL_SHA256_WARNING.to_vec())?;
                Some(NixSha256Digest::from_bytes([0_u8; 32]))
            } else {
                let digest =
                    self.decode_convert_hash(id, span, &hash, Some(HashStringAlgorithm::Sha256))?;
                Some(digest.as_nix_sha256().ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::HashAlgorithmMismatch {
                            id,
                            hash: hash.clone(),
                            expected: b"sha256".to_vec(),
                        },
                        span,
                    )
                })?)
            }
        } else {
            None
        };

        Ok(FetchTarballArguments {
            url,
            name,
            expected_sha256,
        })
    }

    pub(super) fn validate_fetch_tarball_attrs(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let attrs = self
            .heap
            .get_attrs(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        for entry in attrs.iter_lexicographic() {
            let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id,
                        symbol: entry.key,
                    },
                    span,
                )
            })?;
            if !matches!(key, URL_ATTR | NAME_ATTR | SHA256_ATTR) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedFetchTarballAttr {
                        id,
                        attr: key.to_vec(),
                    },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn fetch_tarball_store_name<'a>(
        id: IrId,
        span: Span,
        url: &[u8],
        name: &'a [u8],
    ) -> Result<&'a str, TreeWalkError> {
        nix_compat::store_path::validate_name(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::FetchTarballStoreName {
                    id,
                    url: url.to_vec(),
                    name: name.to_vec(),
                    message: source.to_string(),
                },
                span,
            )
        })
    }

    pub(super) fn fetch_tarball_store_path_from_digest(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        name: &str,
        digest: NixSha256Digest,
    ) -> Result<Vec<u8>, TreeWalkError> {
        self.store_path_bytes_from_fingerprint_parts(id, span, url, b"source", name, digest)
    }

    pub(super) fn check_fetch_tarball_access(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
    ) -> Result<(), TreeWalkError> {
        match parsed.scheme() {
            "file" if self.options.eval_mode() == EvalMode::Restricted => {
                let path = Self::fetchurl_file_path(id, span, url, parsed)?;
                if !self.options.uri_is_allowed(url) {
                    self.check_filesystem_path_access(id, span, path.as_os_str().as_bytes())?;
                }
            }
            "http" | "https"
                if self.options.eval_mode() == EvalMode::Restricted
                    && !self.options.uri_is_allowed(url) =>
            {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::FetchTarballAccessDenied {
                        id,
                        url: url.to_vec(),
                        mode: EvalMode::Restricted,
                    },
                    span,
                ));
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn fetch_tarball_can_reuse_store_path(
        &mut self,
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
        store_path: &[u8],
        expected_digest: NixSha256Digest,
    ) -> Result<bool, TreeWalkError> {
        if !Path::new(OsStr::from_bytes(store_path)).exists() {
            return Ok(false);
        }
        if parsed.scheme() == "file" {
            let source_path = Self::fetchurl_file_path(id, span, url, parsed)?;
            if source_path.exists() {
                return Ok(false);
            }
        }
        if self.can_trust_existing_fetch_tarball_store_path(store_path) {
            return Ok(true);
        }

        self.fetch_tarball_store_path_matches_digest(id, span, store_path, expected_digest)
    }

    pub(super) fn can_trust_existing_fetch_tarball_store_path(&mut self, store_path: &[u8]) -> bool {
        self.should_query_default_nix_store_for_fetch_tarball_path(store_path)
            && self.nix_store_reports_valid_path(store_path)
    }

    pub(super) fn should_query_default_nix_store_for_fetch_tarball_path(
        &self,
        store_path: &[u8],
    ) -> bool {
        self.options.store_dir() == DEFAULT_STORE_DIR
            && is_valid_store_path(store_path, DEFAULT_STORE_DIR)
    }

    /// Reports whether the default Nix store considers `store_path` valid.
    ///
    /// Consults the in-process [`StoreValidityChecker`] (a read-only SQLite read
    /// of the store path database, memoized per run). When the database cannot be
    /// read the checker falls back to [`Self::nix_store_subprocess_reports_valid_path`],
    /// preserving the historical `nix-store --check-validity` behavior.
    pub(super) fn nix_store_reports_valid_path(&mut self, store_path: &[u8]) -> bool {
        // Split the borrow: the checker needs `&mut`, and the fallback is a free
        // function so it captures nothing from `self`.
        let checker = &mut self.store_validity_checker;
        checker.is_valid(store_path, Self::nix_store_subprocess_reports_valid_path)
    }

    /// Reports store path validity by spawning `nix-store --check-validity`.
    ///
    /// This is the fallback used when the in-process path database read is
    /// unavailable; it reproduces the evaluator's original behavior exactly.
    fn nix_store_subprocess_reports_valid_path(store_path: &[u8]) -> bool {
        let Ok(path) = std::str::from_utf8(store_path) else {
            return false;
        };
        Self::nix_store_validity_command(path)
            .status()
            .is_ok_and(|status| status.success())
    }

    pub(super) fn nix_store_validity_command(path: &str) -> std::process::Command {
        let mut command = std::process::Command::new("nix-store");
        command
            .args(["--store", "daemon", "--check-validity", path])
            .env("HOME", "/var/empty")
            .env("XDG_CONFIG_HOME", "/var/empty/.config")
            .env("XDG_CONFIG_DIRS", "/var/empty")
            .env("NIX_USER_CONF_FILES", "")
            .env_remove("AOS_NIX_NATIVE")
            .env_remove("AOS_NIX_NATIVE_VERIFY")
            .env_remove("NIX_REMOTE")
            .env_remove("NIX_CONFIG")
            .env_remove("NIX_CONF_DIR")
            .env_remove("NIX_STORE_DIR")
            .env_remove("NIX_STATE_DIR")
            .env_remove("NIX_LOG_DIR")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        command
    }

    pub(super) fn fetch_tarball_temp_dir(
        id: IrId,
        span: Span,
        url: &[u8],
    ) -> Result<PathBuf, TreeWalkError> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        for _ in 0..128 {
            let index = FETCH_TARBALL_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("aos-nix-fetch-tarball-{pid}-{index}"));
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(Self::fetch_tarball_error(id, span, url, source)),
            }
        }
        Err(TreeWalkError::new(
            TreeWalkErrorKind::FetchTarball {
                id,
                url: url.to_vec(),
                message: "could not allocate a unique temporary unpack directory".to_owned(),
            },
            span,
        ))
    }

    pub(super) fn unpack_fetch_tarball_archive(
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
        contents: &[u8],
        destination: &Path,
    ) -> Result<(), TreeWalkError> {
        match Self::fetch_tarball_compression(parsed, contents) {
            FetchTarballCompression::Tar => {
                Self::unpack_fetch_tarball_reader(id, span, url, Cursor::new(contents), destination)
            }
            FetchTarballCompression::Gzip => {
                let reader = GzDecoder::new(Cursor::new(contents));
                Self::unpack_fetch_tarball_reader(id, span, url, reader, destination)
            }
            FetchTarballCompression::Bzip2 => {
                let reader = BzDecoder::new(Cursor::new(contents));
                Self::unpack_fetch_tarball_reader(id, span, url, reader, destination)
            }
            FetchTarballCompression::Xz => {
                let reader = XzDecoder::new(Cursor::new(contents));
                Self::unpack_fetch_tarball_reader(id, span, url, reader, destination)
            }
            FetchTarballCompression::Zstd => {
                let reader = zstd::stream::read::Decoder::new(Cursor::new(contents))
                    .map_err(|source| Self::fetch_tarball_error(id, span, url, source))?;
                Self::unpack_fetch_tarball_reader(id, span, url, reader, destination)
            }
        }
    }

    pub(super) fn unpack_fetch_tarball_reader<R: Read>(
        id: IrId,
        span: Span,
        url: &[u8],
        reader: R,
        destination: &Path,
    ) -> Result<(), TreeWalkError> {
        let mut archive = tar::Archive::new(reader);
        let entries = archive
            .entries()
            .map_err(|source| Self::fetch_tarball_error(id, span, url, source))?;
        for entry in entries {
            let mut entry =
                entry.map_err(|source| Self::fetch_tarball_error(id, span, url, source))?;
            let unpacked = entry
                .unpack_in(destination)
                .map_err(|source| Self::fetch_tarball_error(id, span, url, source))?;
            if !unpacked {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::FetchTarball {
                        id,
                        url: url.to_vec(),
                        message: "tarball entry would unpack outside destination".to_owned(),
                    },
                    span,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn fetch_tarball_compression(
        parsed: &Url,
        contents: &[u8],
    ) -> FetchTarballCompression {
        if contents.starts_with(&[0x1f, 0x8b]) {
            return FetchTarballCompression::Gzip;
        }
        if contents.starts_with(b"BZh") {
            return FetchTarballCompression::Bzip2;
        }
        if contents.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            return FetchTarballCompression::Xz;
        }
        if contents.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            return FetchTarballCompression::Zstd;
        }

        let path = parsed.path().to_ascii_lowercase();
        if path.ends_with(".tar.gz") || path.ends_with(".tgz") {
            return FetchTarballCompression::Gzip;
        }
        if path.ends_with(".tar.bz2") || path.ends_with(".tbz") || path.ends_with(".tbz2") {
            return FetchTarballCompression::Bzip2;
        }
        if path.ends_with(".tar.xz") || path.ends_with(".txz") {
            return FetchTarballCompression::Xz;
        }
        if path.ends_with(".tar.zst") || path.ends_with(".tar.zstd") {
            return FetchTarballCompression::Zstd;
        }
        FetchTarballCompression::Tar
    }

    pub(super) fn fetch_tarball_unpacked_root(
        id: IrId,
        span: Span,
        url: &[u8],
        unpack_dir: &Path,
    ) -> Result<PathBuf, TreeWalkError> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(unpack_dir)
            .map_err(|source| Self::fetch_tarball_error(id, span, url, source))?
        {
            let entry = entry.map_err(|source| Self::fetch_tarball_error(id, span, url, source))?;
            entries.push(entry.path());
        }
        if entries.len() == 1 {
            let root = entries.pop().ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::FetchTarball {
                        id,
                        url: url.to_vec(),
                        message: "tarball unexpectedly had no unpacked entries".to_owned(),
                    },
                    span,
                )
            })?;
            let metadata = fs::symlink_metadata(&root)
                .map_err(|source| Self::fetch_tarball_error(id, span, url, source))?;
            if metadata.is_dir() {
                return Ok(root);
            }
        }
        Ok(unpack_dir.to_path_buf())
    }
}
