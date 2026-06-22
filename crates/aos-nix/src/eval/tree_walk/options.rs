//! `TreeWalkOptions` construction, validation, and store-/search-path policy helpers.

use super::*;

impl TreeWalkOptions {
    /// Creates evaluator options using Nix-compatible defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates evaluator options with a configured Nix store directory.
    ///
    /// Empty store directories fall back to `/nix/store`. Absolute store
    /// directories are normalized by removing repeated separators, trailing
    /// separators, `.` path components, and reducible `..` path components
    /// before they become visible through `builtins.storeDir`.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `store_dir` is relative.
    pub fn with_store_dir(store_dir: impl Into<Vec<u8>>) -> Result<Self, TreeWalkOptionsError> {
        Ok(Self {
            store_dir: normalize_store_dir(store_dir.into())?,
            ..Self::default()
        })
    }

    /// Creates evaluator options with a configured search-path base directory.
    ///
    /// Relative `NIX_PATH` and `findFile` entry paths are resolved against this
    /// directory when search-path lookup runs. The default is `/`, keeping
    /// evaluation independent from the ambient process working directory unless
    /// a caller explicitly models that C++ Nix setting.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `search_path_base` is relative.
    pub fn with_search_path_base(
        search_path_base: impl Into<Vec<u8>>,
    ) -> Result<Self, TreeWalkOptionsError> {
        let mut options = Self::default();
        options.set_search_path_base(search_path_base)?;
        Ok(options)
    }

    /// Creates evaluator options with a configured path-literal base directory.
    ///
    /// Relative syntactic path literals such as `./foo`, `../bar`, and `foo/bar`
    /// are resolved against this base directory. Leaving it unset keeps
    /// expression evaluation independent from any ambient current directory and
    /// rejects relative path literals.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `path_literal_base` is relative.
    pub fn with_path_literal_base(
        path_literal_base: impl Into<Vec<u8>>,
    ) -> Result<Self, TreeWalkOptionsError> {
        let mut options = Self::default();
        options.set_path_literal_base(path_literal_base)?;
        Ok(options)
    }

    /// Creates evaluator options with a configured home directory.
    ///
    /// Home-relative path literals such as `~/foo` resolve against this
    /// directory outside pure evaluation mode. The evaluator never reads the
    /// ambient process `HOME`, so callers must configure the directory
    /// explicitly when they want to model C++ Nix's impure home expansion.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `home_dir` is empty or relative.
    pub fn with_home_dir(home_dir: impl Into<Vec<u8>>) -> Result<Self, TreeWalkOptionsError> {
        let mut options = Self::default();
        options.set_home_dir(home_dir)?;
        Ok(options)
    }

    /// Creates evaluator options with an explicit evaluation mode.
    pub fn with_eval_mode(eval_mode: EvalMode) -> Self {
        let mut options = Self::default();
        options.set_eval_mode(eval_mode);
        options
    }

    /// Creates evaluator options with one configured environment variable.
    ///
    /// Only variables inserted into these options are visible to
    /// `builtins.getEnv`; the evaluator never reads the ambient process
    /// environment. Pure evaluation mode hides configured variables from
    /// `builtins.getEnv`.
    pub fn with_env_var(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        let mut options = Self::default();
        options.set_env_var(name, value);
        options
    }

    /// Creates evaluator options with a configured target system.
    ///
    /// The target system is exposed through `builtins.currentSystem` outside
    /// pure evaluation mode. Leaving it unset keeps that builtin unavailable
    /// and avoids accidental host introspection.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `current_system` is empty.
    pub fn with_current_system(
        current_system: impl Into<Vec<u8>>,
    ) -> Result<Self, TreeWalkOptionsError> {
        let mut options = Self::default();
        options.set_current_system(current_system)?;
        Ok(options)
    }

    /// Creates evaluator options with a configured evaluation start time.
    ///
    /// The timestamp is exposed through `builtins.currentTime` outside pure
    /// evaluation mode. Leaving it unset keeps that builtin unavailable and
    /// avoids accidental host clock reads.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `current_time` is negative.
    pub fn with_current_time(current_time: i64) -> Result<Self, TreeWalkOptionsError> {
        let mut options = Self::default();
        options.set_current_time(current_time)?;
        Ok(options)
    }

    /// Creates evaluator options with verbose trace output configured.
    pub fn with_trace_verbose(trace_verbose: bool) -> Self {
        let mut options = Self::default();
        options.set_trace_verbose(trace_verbose);
        options
    }

    /// Creates evaluator options with abort-on-warning behavior configured.
    pub fn with_abort_on_warn(abort_on_warn: bool) -> Self {
        let mut options = Self::default();
        options.set_abort_on_warn(abort_on_warn);
        options
    }

    /// Creates evaluator options with a configured maximum nested call depth.
    pub fn with_max_call_depth(max_call_depth: usize) -> Self {
        let mut options = Self::default();
        options.set_max_call_depth(max_call_depth);
        options
    }

    /// Creates evaluator options with experimental TOML timestamp parsing configured.
    pub fn with_parse_toml_timestamps(parse_toml_timestamps: bool) -> Self {
        let mut options = Self::default();
        options.set_parse_toml_timestamps(parse_toml_timestamps);
        options
    }

    /// Creates evaluator options with a configured parse-cache root directory.
    ///
    /// The tree-walk evaluator uses this cache for ordinary filesystem-backed
    /// imports. Scoped imports keep their direct frontend path because they use
    /// different unresolved-global scope rules.
    pub fn with_parse_cache_root(parse_cache_root: impl Into<PathBuf>) -> Self {
        let mut options = Self::default();
        options.set_parse_cache_root(parse_cache_root);
        options
    }

    /// Creates evaluator options with advisory eval-cache trace ingestion configured.
    pub fn with_eval_cache_enabled(eval_cache_enabled: bool) -> Self {
        let mut options = Self::default();
        options.set_eval_cache_enabled(eval_cache_enabled);
        options
    }

    /// Replaces the configured Nix store directory.
    ///
    /// Empty store directories fall back to `/nix/store`. Absolute store
    /// directories are normalized by removing repeated separators, trailing
    /// separators, `.` path components, and reducible `..` path components
    /// before they become visible through `builtins.storeDir`.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `store_dir` is relative.
    pub fn set_store_dir(
        &mut self,
        store_dir: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        self.store_dir = normalize_store_dir(store_dir.into())?;
        Ok(())
    }

    /// Replaces the configured search-path base directory.
    ///
    /// Relative search-path entry paths are resolved against this directory
    /// during `<...>` and `builtins.findFile` lookup.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `search_path_base` is relative.
    pub fn set_search_path_base(
        &mut self,
        search_path_base: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        self.search_path_base = normalize_absolute_path(
            search_path_base.into(),
            b"/",
            TreeWalkOptionsError::RelativeSearchPathBase,
        )?;
        Ok(())
    }

    /// Replaces the base directory used for relative syntactic path literals.
    ///
    /// This setting models C++ Nix's file-evaluation base directory. It is not
    /// used for string-to-path coercion, `builtins.toPath`, or search-path
    /// lookup.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `path_literal_base` is relative.
    pub fn set_path_literal_base(
        &mut self,
        path_literal_base: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        self.path_literal_base = Some(normalize_absolute_path(
            path_literal_base.into(),
            b"/",
            TreeWalkOptionsError::RelativePathLiteralBase,
        )?);
        Ok(())
    }

    /// Clears the base directory used for relative syntactic path literals.
    pub fn clear_path_literal_base(&mut self) {
        self.path_literal_base = None;
    }

    /// Replaces the configured home directory used by `~/...` path literals.
    ///
    /// This setting models C++ Nix's impure home expansion without reading the
    /// ambient process environment. It is intentionally separate from
    /// [`TreeWalkOptions::env_var`], because pure evaluation hides `getEnv`
    /// values and rejects home paths with a different diagnostic surface.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `home_dir` is empty or relative.
    pub fn set_home_dir(
        &mut self,
        home_dir: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        self.home_dir = Some(normalize_required_absolute_path(
            home_dir.into(),
            TreeWalkOptionsError::RelativeHomeDir,
        )?);
        Ok(())
    }

    /// Clears the configured home directory.
    pub fn clear_home_dir(&mut self) {
        self.home_dir = None;
    }

    /// Replaces the evaluation mode.
    pub fn set_eval_mode(&mut self, eval_mode: EvalMode) {
        self.eval_mode = eval_mode;
    }

    /// Appends one allowed filesystem path root for restricted and pure modes.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `path` is relative.
    pub fn add_allowed_path(
        &mut self,
        path: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        let path = normalize_allowed_path(path.into())?;
        self.allowed_paths.push(path);
        Ok(())
    }

    /// Replaces the allowed filesystem path roots for restricted and pure modes.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if any path is relative.
    pub fn set_allowed_paths(
        &mut self,
        paths: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        let mut allowed_paths = Vec::new();
        for path in paths {
            allowed_paths.push(normalize_allowed_path(path)?);
        }
        self.allowed_paths = allowed_paths;
        Ok(())
    }

    /// Clears all allowed filesystem path roots.
    pub fn clear_allowed_paths(&mut self) {
        self.allowed_paths.clear();
    }

    /// Appends one allowed URI prefix for restricted network fetches.
    ///
    /// URI entries are byte prefixes, matching Nix's `allowed-uris` policy
    /// shape. For example, `https://cache.example/` allows every URL under
    /// that prefix, while `github:` allows the whole `github:` scheme.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `uri` is empty.
    pub fn add_allowed_uri(&mut self, uri: impl Into<Vec<u8>>) -> Result<(), TreeWalkOptionsError> {
        let uri = normalize_allowed_uri(uri.into())?;
        self.allowed_uris.push(uri);
        Ok(())
    }

    /// Replaces the allowed URI prefixes for restricted network fetches.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if any URI prefix is empty.
    pub fn set_allowed_uris(
        &mut self,
        uris: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        let mut allowed_uris = Vec::new();
        for uri in uris {
            allowed_uris.push(normalize_allowed_uri(uri)?);
        }
        self.allowed_uris = allowed_uris;
        Ok(())
    }

    /// Clears all allowed URI prefixes.
    pub fn clear_allowed_uris(&mut self) {
        self.allowed_uris.clear();
    }

    #[cfg(test)]
    pub(crate) fn add_fetch_tree_url_response(
        &mut self,
        url: impl Into<Vec<u8>>,
        response: impl Into<Vec<u8>>,
    ) {
        self.fetch_tree_url_responses
            .insert(url.into(), response.into());
    }

    /// Replaces the configured target system.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `current_system` is empty.
    pub fn set_current_system(
        &mut self,
        current_system: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        let current_system = current_system.into();
        if current_system.is_empty() {
            return Err(TreeWalkOptionsError::EmptyCurrentSystem);
        }
        self.current_system = Some(current_system);
        Ok(())
    }

    /// Clears the configured target system.
    pub fn clear_current_system(&mut self) {
        self.current_system = None;
    }

    /// Replaces the configured evaluation start time.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `current_time` is negative.
    pub fn set_current_time(&mut self, current_time: i64) -> Result<(), TreeWalkOptionsError> {
        if current_time < 0 {
            return Err(TreeWalkOptionsError::NegativeCurrentTime);
        }
        self.current_time = Some(current_time);
        Ok(())
    }

    /// Clears the configured evaluation start time.
    pub fn clear_current_time(&mut self) {
        self.current_time = None;
    }

    /// Enables or disables `builtins.traceVerbose` output.
    pub fn set_trace_verbose(&mut self, trace_verbose: bool) {
        self.trace_verbose = trace_verbose;
    }

    /// Enables or disables `builtins.warn` abort-on-warning behavior.
    pub fn set_abort_on_warn(&mut self, abort_on_warn: bool) {
        self.abort_on_warn = abort_on_warn;
    }

    /// Replaces the configured maximum nested call depth.
    pub fn set_max_call_depth(&mut self, max_call_depth: usize) {
        self.max_call_depth = max_call_depth;
    }

    /// Enables or disables experimental TOML timestamp parsing.
    pub fn set_parse_toml_timestamps(&mut self, parse_toml_timestamps: bool) {
        self.parse_toml_timestamps = parse_toml_timestamps;
    }

    /// Replaces a configured environment variable.
    ///
    /// Only variables inserted into these options are visible to
    /// `builtins.getEnv`; absent variables evaluate to an empty string. Pure
    /// evaluation mode hides configured variables from `builtins.getEnv`.
    pub fn set_env_var(&mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.env_vars.insert(name.into(), value.into());
    }

    /// Clears a configured environment variable.
    pub fn clear_env_var(&mut self, name: &[u8]) {
        self.env_vars.remove(name);
    }

    /// Replaces the configured Nix search path.
    ///
    /// The evaluator never reads ambient `NIX_PATH`; callers must provide the
    /// search-path entries they want `<...>`, `builtins.nixPath`, and
    /// `builtins.findFile` to observe.
    pub fn set_nix_path(&mut self, entries: impl IntoIterator<Item = NixSearchPathEntry>) {
        self.nix_path.clear();
        self.nix_path.extend(entries);
    }

    /// Appends one configured Nix search-path entry.
    ///
    /// This method accepts both absolute and relative paths. Relative entries
    /// are resolved against [`TreeWalkOptions::search_path_base`] when lookup
    /// runs.
    ///
    /// # Errors
    ///
    /// This method currently accepts all byte strings and does not fail.
    pub fn add_nix_path_entry(
        &mut self,
        prefix: impl Into<Vec<u8>>,
        path: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        self.nix_path.push(NixSearchPathEntry::new(prefix, path)?);
        Ok(())
    }

    /// Enables or disables ambient Nix search-path lookup.
    ///
    /// When enabled, evaluating `<...>` or `builtins.nixPath` fails before
    /// observing configured search-path entries. Explicit `builtins.findFile`
    /// lists remain evaluable because they do not read the ambient Nix search
    /// path.
    pub fn set_reject_ambient_search_path(&mut self, reject: bool) {
        self.reject_ambient_search_path = reject;
    }

    /// Enables or disables fallback for unconfigured impure builtin constants.
    ///
    /// When enabled, evaluating or testing availability for
    /// `builtins.currentSystem` or `builtins.currentTime` outside pure mode
    /// fails before observing that the constants are absent. Native
    /// instantiation uses this to fall back to C++ Nix, whose CLI populates
    /// those ambient constants.
    pub fn set_reject_unconfigured_impure_builtin_constants(&mut self, reject: bool) {
        self.reject_unconfigured_impure_builtin_constants = reject;
    }

    /// Replaces the parse-cache root directory.
    pub fn set_parse_cache_root(&mut self, parse_cache_root: impl Into<PathBuf>) {
        self.parse_cache_root = Some(parse_cache_root.into());
    }

    /// Disables parse-cache use by this evaluator.
    pub fn clear_parse_cache_root(&mut self) {
        self.parse_cache_root = None;
    }

    /// Enables or disables advisory incremental eval-cache trace ingestion.
    ///
    /// This only controls whether native evaluator handles own an in-memory
    /// [`crate::cache::EvalCache`] and ingest completed evaluator traces into
    /// it. It does not enable memo lookup, persistence, or demand-node
    /// allocation in the tree-walk evaluator.
    pub fn set_eval_cache_enabled(&mut self, eval_cache_enabled: bool) {
        self.eval_cache_enabled = eval_cache_enabled;
    }

    /// Returns the configured Nix store directory.
    pub fn store_dir(&self) -> &[u8] {
        &self.store_dir
    }

    /// Returns the base directory for relative search-path entries.
    pub fn search_path_base(&self) -> &[u8] {
        &self.search_path_base
    }

    /// Returns the base directory for relative syntactic path literals.
    pub fn path_literal_base(&self) -> Option<&[u8]> {
        self.path_literal_base.as_deref()
    }

    /// Returns the configured home directory for `~/...` path literals.
    pub fn home_dir(&self) -> Option<&[u8]> {
        self.home_dir.as_deref()
    }

    /// Returns the configured evaluation mode.
    pub const fn eval_mode(&self) -> EvalMode {
        self.eval_mode
    }

    /// Returns the configured allowed filesystem path roots.
    pub fn allowed_paths(&self) -> &[Vec<u8>] {
        &self.allowed_paths
    }

    /// Returns the configured allowed URI prefixes.
    pub fn allowed_uris(&self) -> &[Vec<u8>] {
        &self.allowed_uris
    }

    pub(crate) fn path_is_allowed(&self, path: &[u8]) -> bool {
        self.allowed_paths
            .iter()
            .any(|allowed| path_is_under_root(path, allowed))
    }

    pub(crate) fn resolved_path_is_allowed(&self, path: &[u8]) -> bool {
        self.path_is_allowed(path)
            || self
                .allowed_paths
                .iter()
                .filter_map(|allowed| canonicalize_policy_path(allowed))
                .any(|allowed| path_is_under_root(path, &allowed))
    }

    pub(crate) fn uri_is_allowed(&self, uri: &[u8]) -> bool {
        self.allowed_uris
            .iter()
            .any(|allowed| uri.starts_with(allowed))
    }

    /// Returns the configured target system, if one is available.
    pub fn current_system(&self) -> Option<&[u8]> {
        self.current_system.as_deref()
    }

    /// Returns the configured evaluation start time, if one is available.
    pub const fn current_time(&self) -> Option<i64> {
        self.current_time
    }

    /// Returns whether `builtins.traceVerbose` emits output.
    pub const fn trace_verbose(&self) -> bool {
        self.trace_verbose
    }

    /// Returns whether `builtins.warn` aborts after emitting a warning.
    pub const fn abort_on_warn(&self) -> bool {
        self.abort_on_warn
    }

    /// Returns the configured maximum nested call depth.
    pub const fn max_call_depth(&self) -> usize {
        self.max_call_depth
    }

    /// Returns whether experimental TOML timestamp parsing is enabled.
    pub const fn parse_toml_timestamps(&self) -> bool {
        self.parse_toml_timestamps
    }

    /// Returns the configured value for an environment variable.
    pub fn env_var(&self, name: &[u8]) -> Option<&[u8]> {
        self.env_vars.get(name).map(Vec::as_slice)
    }

    /// Returns the configured Nix search-path entries.
    pub fn nix_path(&self) -> &[NixSearchPathEntry] {
        &self.nix_path
    }

    /// Returns whether ambient Nix search-path lookup is disabled.
    pub const fn reject_ambient_search_path(&self) -> bool {
        self.reject_ambient_search_path
    }

    /// Returns whether unconfigured impure builtin constants are rejected.
    pub const fn reject_unconfigured_impure_builtin_constants(&self) -> bool {
        self.reject_unconfigured_impure_builtin_constants
    }

    /// Returns the configured parse-cache root directory, if any.
    pub fn parse_cache_root(&self) -> Option<&Path> {
        self.parse_cache_root.as_deref()
    }

    /// Returns whether advisory incremental eval-cache trace ingestion is enabled.
    pub const fn eval_cache_enabled(&self) -> bool {
        self.eval_cache_enabled
    }
}

/// Errors raised while configuring a tree-walk evaluator.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TreeWalkOptionsError {
    /// The configured Nix store directory is not an absolute path.
    #[error("Nix store directory must be absolute")]
    RelativeStoreDir,

    /// The configured search-path base directory is not an absolute path.
    #[error("Nix search-path base directory must be absolute")]
    RelativeSearchPathBase,

    /// The configured path-literal base directory is not an absolute path.
    #[error("Nix path-literal base directory must be absolute")]
    RelativePathLiteralBase,

    /// The configured home directory is empty or not absolute.
    #[error("Nix home directory must be absolute")]
    RelativeHomeDir,

    /// A configured allowed filesystem path is not absolute.
    #[error("Nix allowed filesystem paths must be absolute")]
    RelativeAllowedPath,

    /// A configured allowed URI prefix is empty.
    #[error("Nix allowed URI prefixes must not be empty")]
    EmptyAllowedUri,

    /// The configured target system is empty.
    #[error("Nix currentSystem value must not be empty")]
    EmptyCurrentSystem,

    /// The configured evaluation start time is negative.
    #[error("Nix currentTime value must not be negative")]
    NegativeCurrentTime,
}

pub(crate) fn normalize_store_dir(store_dir: Vec<u8>) -> Result<Vec<u8>, TreeWalkOptionsError> {
    normalize_absolute_path(
        store_dir,
        DEFAULT_STORE_DIR,
        TreeWalkOptionsError::RelativeStoreDir,
    )
}

pub(crate) fn normalize_absolute_path(
    path: Vec<u8>,
    empty_default: &[u8],
    relative_error: TreeWalkOptionsError,
) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if path.is_empty() {
        return Ok(empty_default.to_vec());
    }
    if !path.starts_with(b"/") {
        return Err(relative_error);
    }

    Ok(normalize_absolute_path_bytes(&path))
}

pub(crate) fn normalize_allowed_path(path: Vec<u8>) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if path.is_empty() || !path.starts_with(b"/") {
        return Err(TreeWalkOptionsError::RelativeAllowedPath);
    }

    Ok(normalize_absolute_path_bytes(&path))
}

pub(crate) fn normalize_allowed_uri(uri: Vec<u8>) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if uri.is_empty() {
        return Err(TreeWalkOptionsError::EmptyAllowedUri);
    }

    Ok(uri)
}

pub(crate) fn normalize_required_absolute_path(
    path: Vec<u8>,
    relative_error: TreeWalkOptionsError,
) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if path.is_empty() || !path.starts_with(b"/") {
        return Err(relative_error);
    }

    Ok(normalize_absolute_path_bytes(&path))
}

pub(crate) fn normalize_absolute_path_bytes(path: &[u8]) -> Vec<u8> {
    let mut components = Vec::new();
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            components.pop();
            continue;
        }
        components.push(component);
    }

    let mut normalized = Vec::with_capacity(path.len());
    for component in components {
        normalized.push(b'/');
        normalized.extend_from_slice(component);
    }

    if normalized.is_empty() {
        normalized.push(b'/');
    }

    normalized
}

pub(crate) fn path_is_under_root(path: &[u8], root: &[u8]) -> bool {
    if root == b"/" {
        return path.starts_with(b"/");
    }
    path == root || (path.starts_with(root) && path.get(root.len()) == Some(&b'/'))
}

pub(crate) fn canonicalize_policy_path(path: &[u8]) -> Option<Vec<u8>> {
    let path = Path::new(OsStr::from_bytes(path));
    let resolved = fs::canonicalize(path).ok()?;
    Some(normalize_absolute_path_bytes(
        resolved.as_os_str().as_bytes(),
    ))
}

pub(crate) fn is_valid_store_path(path: &[u8], store_dir: &[u8]) -> bool {
    if path.len() <= store_dir.len() + 34 || !path.starts_with(store_dir) {
        return false;
    }
    if path.get(store_dir.len()) != Some(&b'/') {
        return false;
    }
    let name = &path[store_dir.len() + 1..];
    if name.len() < 34 || name.get(32) != Some(&b'-') {
        return false;
    }
    let store_name = &name[33..];
    if store_name.is_empty() || store_name.len() > 211 || store_name == b"." || store_name == b".."
    {
        return false;
    }
    name[..32].iter().all(|byte| is_nix_base32_byte(*byte))
        && store_name.iter().all(|byte| is_store_name_byte(*byte))
}

pub(crate) fn store_path_root<'a>(path: &'a [u8], store_dir: &[u8]) -> Option<&'a [u8]> {
    if path.len() <= store_dir.len() + 34 || !path.starts_with(store_dir) {
        return None;
    }
    if path.get(store_dir.len()) != Some(&b'/') {
        return None;
    }
    let suffix = &path[store_dir.len() + 1..];
    let component_len = suffix
        .iter()
        .position(|byte| *byte == b'/')
        .unwrap_or(suffix.len());
    let root_len = store_dir.len() + 1 + component_len;
    let root = &path[..root_len];
    is_valid_store_path(root, store_dir).then_some(root)
}

pub(crate) fn is_nix_base32_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'a'
            | b'b'
            | b'c'
            | b'd'
            | b'f'
            | b'g'
            | b'h'
            | b'i'
            | b'j'
            | b'k'
            | b'l'
            | b'm'
            | b'n'
            | b'p'
            | b'q'
            | b'r'
            | b's'
            | b'v'
            | b'w'
            | b'x'
            | b'y'
            | b'z'
    )
}

pub(crate) fn is_store_name_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'+'
            | b'-'
            | b'.'
            | b'_'
            | b'?'
            | b'='
    )
}

pub(crate) fn file_type_name(file_type: fs::FileType) -> &'static [u8] {
    if file_type.is_file() {
        b"regular"
    } else if file_type.is_dir() {
        b"directory"
    } else if file_type.is_symlink() {
        b"symlink"
    } else {
        b"unknown"
    }
}

pub(crate) fn path_without_trailing_path_markers(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    loop {
        let previous_end = end;
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        if end > 2 && path[end - 2] == b'/' && path[end - 1] == b'.' {
            end -= 2;
            continue;
        }
        if end == 2 && path[0] == b'/' && path[1] == b'.' {
            end = 1;
        }
        if end == previous_end {
            break;
        }
    }
    &path[..end]
}

pub(crate) fn path_exists_requires_directory(path: &[u8]) -> bool {
    path.ends_with(b"/") || path.ends_with(b"/.")
}

pub(crate) fn search_path_suffix<'a>(prefix: &[u8], lookup: &'a [u8]) -> Option<&'a [u8]> {
    if prefix.is_empty() {
        return Some(lookup);
    }
    if lookup == prefix {
        return Some(&[]);
    }
    lookup
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_prefix(b"/"))
}

pub(crate) fn search_path_literal_lookup<'a>(
    id: IrId,
    span: Span,
    literal: &'a [u8],
) -> Result<&'a [u8], TreeWalkError> {
    literal
        .strip_prefix(b"<")
        .and_then(|literal| literal.strip_suffix(b">"))
        .ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSearchPathLiteral {
                    id,
                    literal: literal.to_vec(),
                },
                span,
            )
        })
}

pub(crate) fn join_search_path(
    id: IrId,
    span: Span,
    base: &[u8],
    path: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, TreeWalkError> {
    let mut joined = Vec::new();

    if path.starts_with(b"/") {
        append_search_path_component(id, span, &mut joined, path)?;
    } else {
        append_search_path_component(id, span, &mut joined, base)?;
        append_search_path_component(id, span, &mut joined, path)?;
    }

    append_search_path_component(id, span, &mut joined, suffix)?;
    TreeWalk::absolute_path_bytes_for_node(id, span, &joined)
}

pub(crate) fn join_path_literal(
    id: IrId,
    span: Span,
    base: &[u8],
    path: &[u8],
) -> Result<Vec<u8>, TreeWalkError> {
    let mut joined = Vec::new();
    append_search_path_component(id, span, &mut joined, base)?;
    append_search_path_component(id, span, &mut joined, path)?;
    TreeWalk::absolute_path_bytes_for_node(id, span, &joined)
}

pub(crate) fn append_search_path_component(
    id: IrId,
    span: Span,
    joined: &mut Vec<u8>,
    component: &[u8],
) -> Result<(), TreeWalkError> {
    if component.is_empty() {
        return Ok(());
    }

    let needs_separator = !joined.is_empty() && !joined.ends_with(b"/");
    let additional = component
        .len()
        .checked_add(usize::from(needs_separator))
        .ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
    let len = joined.len().checked_add(additional).ok_or_else(|| {
        TreeWalkError::new(
            TreeWalkErrorKind::ByteAllocationFailed {
                id,
                len: usize::MAX,
            },
            span,
        )
    })?;
    joined.try_reserve_exact(additional).map_err(|_| {
        TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
    })?;

    if needs_separator {
        joined.push(b'/');
    }
    joined.extend_from_slice(component);
    Ok(())
}
