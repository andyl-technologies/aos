//! Forge (GitHub/GitLab/SourceHut) ref resolution and `fetchTree` argument assembly.

use super::*;

struct SourcehutLsRemoteLine<'a> {
    target: &'a [u8],
    reference: Option<&'a [u8]>,
}

impl TreeWalk {
    pub(super) fn resolve_fetch_tree_github_ref(
        &self,
        id: IrId,
        span: Span,
        canonical_uri: &[u8],
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
        reference: &[u8],
        check_url_access: bool,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let url = Self::fetch_tree_github_ref_url(id, span, owner, repo, host, reference)?;
        let parsed = Self::parse_fetch_tree_url(id, span, &url)?;
        if check_url_access {
            self.check_fetch_tree_url_access(id, span, &url, &parsed)?;
        }
        let response =
            self.fetch_tree_json_api_bytes(id, span, &url, &parsed, "application/vnd.github+json")?;
        let rev =
            Self::fetch_tree_github_rev_from_commit_response(id, span, canonical_uri, &response)?;
        self.canonical_flake_ref_rev(id, span, &rev)
    }

    pub(super) fn resolve_fetch_tree_forge_ref(
        &self,
        id: IrId,
        span: Span,
        canonical_uri: &[u8],
        input_type: &[u8],
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
        reference: &[u8],
        check_url_access: bool,
    ) -> Result<Vec<u8>, TreeWalkError> {
        match input_type {
            b"github" => self.resolve_fetch_tree_github_ref(
                id,
                span,
                canonical_uri,
                owner,
                repo,
                host,
                reference,
                check_url_access,
            ),
            b"gitlab" => self.resolve_fetch_tree_gitlab_ref(
                id,
                span,
                canonical_uri,
                owner,
                repo,
                host,
                reference,
                check_url_access,
            ),
            b"sourcehut" => self.resolve_fetch_tree_sourcehut_ref(
                id,
                span,
                canonical_uri,
                owner,
                repo,
                host,
                reference,
                check_url_access,
            ),
            _ => Err(Self::unsupported_fetch_tree_feature(
                id,
                span,
                "forge reference resolution",
            )),
        }
    }

    pub(super) fn fetch_tree_github_ref_url(
        id: IrId,
        span: Span,
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
        reference: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let owner = Self::percent_encode_flake_ref(owner, b"");
        let repo = Self::percent_encode_flake_ref(repo, b"");
        let reference = Self::percent_encode_flake_ref(reference, b"");
        let mut url = match host {
            None => b"https://api.github.com/repos/".to_vec(),
            Some(host) if host == b"github.com" => b"https://api.github.com/repos/".to_vec(),
            Some(host) => {
                let host = std::str::from_utf8(host)
                    .map_err(|source| Self::fetch_tree_error(id, span, host, source))?;
                let mut url = b"https://".to_vec();
                url.extend_from_slice(host.as_bytes());
                url.extend_from_slice(b"/api/v3/repos/");
                url
            }
        };
        url.extend_from_slice(&owner);
        url.push(b'/');
        url.extend_from_slice(&repo);
        url.extend_from_slice(b"/commits/");
        url.extend_from_slice(&reference);
        Ok(url)
    }

    pub(super) fn resolve_fetch_tree_gitlab_ref(
        &self,
        id: IrId,
        span: Span,
        canonical_uri: &[u8],
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
        reference: &[u8],
        check_url_access: bool,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let url = Self::fetch_tree_gitlab_ref_url(id, span, owner, repo, host, reference)?;
        let parsed = Self::parse_fetch_tree_url(id, span, &url)?;
        if check_url_access {
            self.check_fetch_tree_url_access(id, span, &url, &parsed)?;
        }
        let response =
            self.fetch_tree_json_api_bytes(id, span, &url, &parsed, "application/json")?;
        let rev =
            Self::fetch_tree_gitlab_rev_from_commit_response(id, span, canonical_uri, &response)?;
        self.canonical_flake_ref_rev(id, span, &rev)
    }

    pub(super) fn fetch_tree_gitlab_ref_url(
        id: IrId,
        span: Span,
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
        reference: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let owner = Self::percent_encode_flake_ref(owner, b"");
        let repo = Self::percent_encode_flake_ref(repo, b"");
        let reference = Self::percent_encode_flake_ref(reference, b"");
        let host = match host {
            Some(host) => std::str::from_utf8(host)
                .map_err(|source| Self::fetch_tree_error(id, span, host, source))?,
            None => "gitlab.com",
        };
        let mut url = b"https://".to_vec();
        url.extend_from_slice(host.as_bytes());
        url.extend_from_slice(b"/api/v4/projects/");
        url.extend_from_slice(&owner);
        url.extend_from_slice(b"%2F");
        url.extend_from_slice(&repo);
        url.extend_from_slice(b"/repository/commits/");
        url.extend_from_slice(&reference);
        Ok(url)
    }

    pub(super) fn resolve_fetch_tree_sourcehut_ref(
        &self,
        id: IrId,
        span: Span,
        canonical_uri: &[u8],
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
        reference: &[u8],
        check_url_access: bool,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let reference = if reference == b"HEAD" {
            self.resolve_fetch_tree_sourcehut_head_ref(
                id,
                span,
                canonical_uri,
                owner,
                repo,
                host,
                check_url_access,
            )?
        } else {
            Self::fetch_tree_sourcehut_named_ref(reference)
        };
        let url = Self::fetch_tree_sourcehut_refs_url(id, span, owner, repo, host)?;
        let parsed = Self::parse_fetch_tree_url(id, span, &url)?;
        if check_url_access {
            self.check_fetch_tree_url_access(id, span, &url, &parsed)?;
        }
        let response = self.fetch_tree_url_bytes(id, span, &url, &parsed)?;
        let rev = Self::fetch_tree_sourcehut_rev_from_refs_response(
            id,
            span,
            canonical_uri,
            &reference,
            &response,
        )?;
        self.canonical_flake_ref_rev(id, span, &rev)
    }

    pub(super) fn resolve_fetch_tree_sourcehut_head_ref(
        &self,
        id: IrId,
        span: Span,
        canonical_uri: &[u8],
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
        check_url_access: bool,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let url = Self::fetch_tree_sourcehut_head_url(id, span, owner, repo, host)?;
        let parsed = Self::parse_fetch_tree_url(id, span, &url)?;
        if check_url_access {
            self.check_fetch_tree_url_access(id, span, &url, &parsed)?;
        }
        let response = self.fetch_tree_url_bytes(id, span, &url, &parsed)?;
        let first_line = response
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        let line = first_line.strip_suffix(b"\r").unwrap_or(first_line);
        let Some(line) = Self::parse_sourcehut_ls_remote_line(line) else {
            return Err(Self::fetch_tree_error(
                id,
                span,
                canonical_uri,
                "SourceHut HEAD response is invalid",
            ));
        };
        Ok(line.target.to_vec())
    }

    fn fetch_tree_sourcehut_named_ref(reference: &[u8]) -> Vec<u8> {
        let mut out = b"refs/heads/".to_vec();
        out.extend_from_slice(reference);
        out.push(0);
        out.extend_from_slice(b"refs/tags/");
        out.extend_from_slice(reference);
        out
    }

    pub(super) fn fetch_tree_sourcehut_head_url(
        id: IrId,
        span: Span,
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut url = Self::fetch_tree_sourcehut_base_url(id, span, owner, repo, host)?;
        url.extend_from_slice(b"/HEAD");
        Ok(url)
    }

    pub(super) fn fetch_tree_sourcehut_refs_url(
        id: IrId,
        span: Span,
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut url = Self::fetch_tree_sourcehut_base_url(id, span, owner, repo, host)?;
        url.extend_from_slice(b"/info/refs");
        Ok(url)
    }

    pub(super) fn fetch_tree_sourcehut_base_url(
        id: IrId,
        span: Span,
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
    ) -> Result<Vec<u8>, TreeWalkError> {
        let owner = Self::percent_encode_flake_ref(owner, b"");
        let repo = Self::percent_encode_flake_ref(repo, b"");
        let host = match host {
            Some(host) => std::str::from_utf8(host)
                .map_err(|source| Self::fetch_tree_error(id, span, host, source))?,
            None => "git.sr.ht",
        };
        let mut url = b"https://".to_vec();
        url.extend_from_slice(host.as_bytes());
        url.push(b'/');
        url.extend_from_slice(&owner);
        url.push(b'/');
        url.extend_from_slice(&repo);
        Ok(url)
    }

    pub(super) fn fetch_tree_json_api_bytes(
        &self,
        id: IrId,
        span: Span,
        url: &[u8],
        parsed: &Url,
        accept: &'static str,
    ) -> Result<Vec<u8>, TreeWalkError> {
        match parsed.scheme() {
            "http" | "https" => {
                #[cfg(test)]
                if let Some(response) = self.options.fetch_tree_url_responses.get(url) {
                    return Ok(response.clone());
                }
                #[cfg(test)]
                if !self.options.fetch_tree_url_responses.is_empty() {
                    return Err(Self::fetch_tree_error(
                        id,
                        span,
                        url,
                        "missing test fetchTree URL response",
                    ));
                }

                let client = reqwest::blocking::Client::builder()
                    .no_gzip()
                    .no_brotli()
                    .no_zstd()
                    .no_deflate()
                    .build()
                    .map_err(|source| Self::fetch_tree_error(id, span, url, source))?;
                let response = client
                    .get(parsed.as_str())
                    .header(reqwest::header::ACCEPT, accept)
                    .header(reqwest::header::ACCEPT_ENCODING, "identity")
                    .header(reqwest::header::USER_AGENT, "aos-nix")
                    .send()
                    .map_err(|source| Self::fetch_tree_error(id, span, url, source))?;
                let response = response
                    .error_for_status()
                    .map_err(|source| Self::fetch_tree_error(id, span, url, source))?;
                response
                    .bytes()
                    .map(|bytes| bytes.to_vec())
                    .map_err(|source| Self::fetch_tree_error(id, span, url, source))
            }
            scheme => Err(TreeWalkError::new(
                TreeWalkErrorKind::FetchTree {
                    id,
                    input: url.to_vec(),
                    message: format!("unsupported URL scheme {scheme:?}"),
                },
                span,
            )),
        }
    }

    pub(super) fn fetch_tree_gitlab_rev_from_commit_response(
        id: IrId,
        span: Span,
        input: &[u8],
        response: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let value = serde_json::from_slice::<JsonValue>(response).map_err(|source| {
            Self::fetch_tree_error(
                id,
                span,
                input,
                format!("invalid GitLab response: {source}"),
            )
        })?;
        let sha = value.get("id").and_then(JsonValue::as_str).ok_or_else(|| {
            Self::fetch_tree_error(id, span, input, "GitLab response is missing commit id")
        })?;
        if !Self::is_git_rev(sha.as_bytes()) {
            return Err(Self::fetch_tree_error(
                id,
                span,
                input,
                "GitLab response commit id is invalid",
            ));
        }
        Ok(sha.as_bytes().to_vec())
    }

    pub(super) fn fetch_tree_sourcehut_rev_from_refs_response(
        id: IrId,
        span: Span,
        input: &[u8],
        reference_pattern: &[u8],
        response: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        for raw_line in response.split(|byte| *byte == b'\n') {
            let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
            let Some(line) = Self::parse_sourcehut_ls_remote_line(line) else {
                continue;
            };
            let Some(name) = line.reference else {
                continue;
            };
            if !Self::sourcehut_ref_pattern_matches(reference_pattern, name) {
                continue;
            }
            if !Self::is_git_rev(line.target) {
                return Err(Self::fetch_tree_error(
                    id,
                    span,
                    input,
                    "SourceHut response commit id is invalid",
                ));
            }
            return Ok(line.target.to_vec());
        }

        Err(Self::fetch_tree_error(
            id,
            span,
            input,
            "SourceHut response is missing the requested ref",
        ))
    }

    fn sourcehut_ref_pattern_matches(pattern: &[u8], name: &[u8]) -> bool {
        if let Some(split) = pattern.iter().position(|byte| *byte == 0) {
            let head = &pattern[..split];
            let tag = &pattern[(split + 1)..];
            return name == head || name == tag;
        }
        name == pattern
    }

    fn parse_sourcehut_ls_remote_line(line: &[u8]) -> Option<SourcehutLsRemoteLine<'_>> {
        let rest = if let Some(rest) = line.strip_prefix(b"ref:") {
            let rest = rest
                .iter()
                .position(|byte| *byte != b' ')
                .map_or(&[][..], |index| &rest[index..]);
            rest
        } else {
            line
        };
        let target_end = rest
            .iter()
            .position(|byte| byte.is_ascii_whitespace())
            .unwrap_or(rest.len());
        if target_end == 0 {
            return None;
        }
        let target = &rest[..target_end];
        let remaining = &rest[target_end..];
        let reference = if remaining.is_empty() {
            None
        } else if remaining[0] == b'\t' {
            let reference_start = remaining
                .iter()
                .position(|byte| *byte != b'\t')
                .unwrap_or(remaining.len());
            (reference_start < remaining.len()).then_some(&remaining[reference_start..])
        } else {
            return None;
        };
        Some(SourcehutLsRemoteLine { target, reference })
    }

    pub(super) fn fetch_tree_github_rev_from_commit_response(
        id: IrId,
        span: Span,
        input: &[u8],
        response: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let value = serde_json::from_slice::<JsonValue>(response).map_err(|source| {
            Self::fetch_tree_error(
                id,
                span,
                input,
                format!("invalid GitHub response: {source}"),
            )
        })?;
        let sha = value
            .get("sha")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                Self::fetch_tree_error(id, span, input, "GitHub response is missing commit sha")
            })?;
        if !Self::is_git_rev(sha.as_bytes()) {
            return Err(Self::fetch_tree_error(
                id,
                span,
                input,
                "GitHub response commit sha is invalid",
            ));
        }
        Ok(sha.as_bytes().to_vec())
    }

    pub(super) fn fetch_tree_git_flake_ref_arguments(
        &self,
        id: IrId,
        span: Span,
        input: &[u8],
        attrs: &FlakeRefAttrs,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
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
                ALL_REFS_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                REV_COUNT_ATTR,
                EXPORT_IGNORE_ATTR,
                VERIFY_COMMIT_ATTR,
                KEYTYPE_ATTR,
                PUBLIC_KEY_ATTR,
                PUBLIC_KEYS_ATTR,
                DIR_ATTR,
            ],
        )?;
        let extra_query = self.fetch_tree_git_flake_ref_verified_fetch_query(id, span, attrs)?;
        let url = Self::required_flake_ref_string_attr(id, span, attrs, URL_ATTR)?;
        let transport_url = Self::fetch_tree_git_flake_ref_transport_url(
            id,
            span,
            input,
            url,
            attrs.contains_key(DIR_ATTR),
        )?;
        let dir =
            Self::optional_flake_ref_string_attr(id, span, attrs, DIR_ATTR)?.map(ToOwned::to_owned);
        let submodules =
            Self::optional_flake_ref_bool_attr(id, span, attrs, SUBMODULES_ATTR)?.unwrap_or(false);
        Ok(FetchTreeArguments::Git {
            args: FetchGitArguments {
                url: url.to_vec(),
                transport_url,
                name: "source".to_owned(),
                rev: Self::optional_flake_ref_string_attr(id, span, attrs, REV_ATTR)?
                    .map(ToOwned::to_owned),
                reference: Self::optional_flake_ref_string_attr(id, span, attrs, REF_ATTR)?
                    .map(ToOwned::to_owned),
                submodules,
                shallow: Self::optional_flake_ref_bool_attr(id, span, attrs, SHALLOW_ATTR)?
                    .unwrap_or(true),
                all_refs: Self::optional_flake_ref_bool_attr(id, span, attrs, ALL_REFS_ATTR)?
                    .unwrap_or(false),
                export_ignore: Self::optional_flake_ref_bool_attr(
                    id,
                    span,
                    attrs,
                    EXPORT_IGNORE_ATTR,
                )?
                .unwrap_or(!submodules),
                extra_query,
            },
            dir,
            expected_nar_hash: self.optional_flake_ref_nar_hash_attr(id, span, attrs)?,
            expected_last_modified: Self::optional_flake_ref_i64_attr(
                id,
                span,
                attrs,
                LAST_MODIFIED_ATTR,
            )?,
            expected_rev_count: Self::optional_flake_ref_usize_attr(
                id,
                span,
                attrs,
                REV_COUNT_ATTR,
            )?,
            dirty_rev: None,
            dirty_short_rev: None,
        })
    }

    pub(super) fn fetch_tree_forge_archive_url(
        id: IrId,
        span: Span,
        input_type: &[u8],
        owner: &[u8],
        repo: &[u8],
        host: Option<&[u8]>,
        rev: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let owner = Self::percent_encode_flake_ref(owner, b"");
        let repo = Self::percent_encode_flake_ref(repo, b"");
        let rev = Self::percent_encode_flake_ref(rev, b"");
        let host = match host {
            Some(host) => std::str::from_utf8(host)
                .map_err(|source| Self::fetch_tree_error(id, span, host, source))?,
            None => Self::default_forge_host(input_type).ok_or_else(|| {
                Self::fetch_tree_error(id, span, input_type, "unsupported forge input type")
            })?,
        };
        let mut url = b"https://".to_vec();
        url.extend_from_slice(host.as_bytes());
        match input_type {
            b"github" if host == "github.com" => {
                url.push(b'/');
                url.extend_from_slice(&owner);
                url.push(b'/');
                url.extend_from_slice(&repo);
                url.extend_from_slice(b"/archive/");
                url.extend_from_slice(&rev);
                url.extend_from_slice(b".tar.gz");
            }
            b"github" => {
                url.extend_from_slice(b"/api/v3/repos/");
                url.extend_from_slice(&owner);
                url.push(b'/');
                url.extend_from_slice(&repo);
                url.extend_from_slice(b"/tarball/");
                url.extend_from_slice(&rev);
            }
            b"gitlab" => {
                url.extend_from_slice(b"/api/v4/projects/");
                url.extend_from_slice(&owner);
                url.extend_from_slice(b"%2F");
                url.extend_from_slice(&repo);
                url.extend_from_slice(b"/repository/archive.tar.gz?sha=");
                url.extend_from_slice(&rev);
            }
            b"sourcehut" => {
                url.push(b'/');
                url.extend_from_slice(&owner);
                url.push(b'/');
                url.extend_from_slice(&repo);
                url.extend_from_slice(b"/archive/");
                url.extend_from_slice(&rev);
                url.extend_from_slice(b".tar.gz");
            }
            _ => {
                return Err(Self::fetch_tree_error(
                    id,
                    span,
                    input_type,
                    "unsupported forge input type",
                ));
            }
        }
        Ok(url)
    }

    pub(super) fn default_forge_host(input_type: &[u8]) -> Option<&'static str> {
        match input_type {
            b"github" => Some("github.com"),
            b"gitlab" => Some("gitlab.com"),
            b"sourcehut" => Some("git.sr.ht"),
            _ => None,
        }
    }

    pub(super) fn validate_forge_path_segment(
        id: IrId,
        span: Span,
        value: &[u8],
        message: &'static str,
    ) -> Result<(), TreeWalkError> {
        if value.is_empty() || value.contains(&b'/') {
            return Err(Self::fetch_tree_error(id, span, value, message));
        }
        Ok(())
    }

    pub(super) fn fetch_tree_path_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        self.validate_fetch_tree_attrs(
            id,
            span,
            value,
            &[
                TYPE_ATTR,
                PATH_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                REV_ATTR,
                REV_COUNT_ATTR,
            ],
        )?;
        let path_value = self.required_attr_value_by_name(id, value, PATH_ATTR, span)?;
        let path = self.fetch_tree_path_argument_bytes(id, span, path_value)?;
        let expected_nar_hash = self.optional_fetch_tree_nar_hash_attr(id, span, value)?;
        let expected_last_modified =
            self.optional_fetch_tree_int_attr(id, span, value, LAST_MODIFIED_ATTR)?;
        let rev = self.optional_fetch_tree_string_attr(id, span, value, REV_ATTR)?;
        let rev_count = self.optional_fetch_tree_usize_attr(id, span, value, REV_COUNT_ATTR)?;
        Ok(FetchTreeArguments::Path {
            path,
            expected_nar_hash,
            expected_last_modified,
            rev,
            rev_count,
        })
    }

    pub(super) fn fetch_tree_git_flake_ref_transport_url(
        id: IrId,
        span: Span,
        input: &[u8],
        url: &[u8],
        strip_dir: bool,
    ) -> Result<Option<Vec<u8>>, TreeWalkError> {
        let text = std::str::from_utf8(url)
            .map_err(|source| Self::fetch_tree_error(id, span, input, source))?;
        let parsed =
            Url::parse(text).map_err(|source| Self::fetch_tree_error(id, span, input, source))?;
        let mut query = Self::decode_flake_ref_query(id, span, input, parsed.query())?;
        let mut stripped = false;

        if query.remove(NAR_HASH_ATTR).is_some() {
            stripped = true;
        }
        if query.remove(LAST_MODIFIED_ATTR).is_some() {
            stripped = true;
        }
        if query.remove(REV_COUNT_ATTR).is_some() {
            stripped = true;
        }
        if strip_dir && query.remove(DIR_ATTR).is_some() {
            stripped = true;
        }
        for key in [
            VERIFY_COMMIT_ATTR,
            KEYTYPE_ATTR,
            PUBLIC_KEY_ATTR,
            PUBLIC_KEYS_ATTR,
        ] {
            if query.remove(key).is_some() {
                stripped = true;
            }
        }

        if !stripped {
            return Ok(None);
        }

        Self::flake_ref_url_with_scheme_and_query(
            id,
            span,
            input,
            &parsed,
            None,
            query,
            BTreeMap::new(),
        )
        .map(Some)
    }

    pub(super) fn fetch_tree_url_with_dir_metadata(
        id: IrId,
        span: Span,
        url: &[u8],
        dir: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), TreeWalkError> {
        let transport_url = url.to_vec();
        let Some(dir) = dir else {
            return Ok((transport_url.clone(), transport_url));
        };
        let parsed = Self::parse_fetch_tree_url(id, span, url)?;
        let mut updates = BTreeMap::new();
        updates.insert(DIR_ATTR.to_vec(), dir.to_vec());
        let canonical_url = Self::flake_ref_url_with_scheme_and_query(
            id,
            span,
            url,
            &parsed,
            None,
            Self::decode_flake_ref_query(id, span, url, parsed.query())?,
            updates,
        )?;
        Ok((canonical_url, transport_url))
    }

    pub(super) fn fetch_tree_transport_url_without_dir(
        id: IrId,
        span: Span,
        url: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let parsed = Self::parse_fetch_tree_url(id, span, url)?;
        let mut query = Self::decode_flake_ref_query(id, span, url, parsed.query())?;
        if query.remove(DIR_ATTR).is_none() {
            return Ok(url.to_vec());
        }
        Self::flake_ref_url_with_scheme_and_query(
            id,
            span,
            url,
            &parsed,
            None,
            query,
            BTreeMap::new(),
        )
    }

    pub(super) fn fetch_tree_file_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        self.validate_fetch_tree_attrs(
            id,
            span,
            value,
            &[
                TYPE_ATTR,
                URL_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                REV_ATTR,
                REV_COUNT_ATTR,
                UNPACK_ATTR,
            ],
        )?;
        let url = self.required_fetch_tree_url(id, span, value)?;
        let expected_nar_hash = self.optional_fetch_tree_nar_hash_attr(id, span, value)?;
        let expected_last_modified =
            self.optional_fetch_tree_int_attr(id, span, value, LAST_MODIFIED_ATTR)?;
        let rev = self.optional_fetch_tree_string_attr(id, span, value, REV_ATTR)?;
        let rev_count = self.optional_fetch_tree_usize_attr(id, span, value, REV_COUNT_ATTR)?;
        let _unpack = self.optional_fetch_tree_bool_attr(id, span, value, UNPACK_ATTR, false)?;
        Ok(FetchTreeArguments::File {
            url,
            expected_nar_hash,
            expected_last_modified,
            rev,
            rev_count,
        })
    }

    pub(super) fn fetch_tree_tarball_arguments(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<FetchTreeArguments, TreeWalkError> {
        self.validate_fetch_tree_attrs(
            id,
            span,
            value,
            &[
                TYPE_ATTR,
                URL_ATTR,
                NAR_HASH_ATTR,
                LAST_MODIFIED_ATTR,
                REV_ATTR,
                REV_COUNT_ATTR,
                UNPACK_ATTR,
                DIR_ATTR,
            ],
        )?;
        let raw_url = self.required_fetch_tree_url(id, span, value)?;
        let dir = self.optional_fetch_tree_string_attr(id, span, value, DIR_ATTR)?;
        let (url, transport_url) =
            Self::fetch_tree_url_with_dir_metadata(id, span, &raw_url, dir.as_deref())?;
        let expected_nar_hash = self.optional_fetch_tree_nar_hash_attr(id, span, value)?;
        let expected_last_modified =
            self.optional_fetch_tree_int_attr(id, span, value, LAST_MODIFIED_ATTR)?;
        let rev = self.optional_fetch_tree_string_attr(id, span, value, REV_ATTR)?;
        let rev_count = self.optional_fetch_tree_usize_attr(id, span, value, REV_COUNT_ATTR)?;
        let _unpack = self.optional_fetch_tree_bool_attr(id, span, value, UNPACK_ATTR, true)?;
        Ok(FetchTreeArguments::Tarball {
            url,
            transport_url,
            dir,
            expected_nar_hash,
            expected_last_modified,
            last_modified_from_lock: false,
            rev,
            rev_count,
        })
    }

}

mod forge_git;
