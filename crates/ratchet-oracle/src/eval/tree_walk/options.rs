//! `TreeWalkOptions` construction, validation, and store-/search-path policy helpers.

use super::*;

mod boundary_memo;
mod eval_stats;
mod memo;
mod path_policy;
mod result_fingerprint;
mod root_cutoff;
mod session_machine;

pub use boundary_memo::BoundaryMemoOptions;
pub use memo::{MemoNetMode, MemoNetOptions, MemoOptions};

// Retains the former crate-visible helper paths, even when no current caller uses them.
#[allow(unused_imports)]
pub(crate) use path_policy::{
    append_search_path_component, file_type_name, is_nix_base32_byte, is_store_name_byte,
    is_valid_store_path, join_path_literal, join_search_path, normalize_absolute_path,
    normalize_allowed_path, normalize_allowed_uri, normalize_required_absolute_path,
    normalize_store_dir, path_exists_requires_directory, path_is_under_root,
    path_without_trailing_path_markers, search_path_literal_lookup, search_path_suffix,
    store_path_root,
};
pub use path_policy::{canonicalize_policy_path, normalize_absolute_path_bytes};

impl TreeWalkOptions {
    /// Installs a sink for direct `config.<path>` reads actually executed by
    /// imported modules.
    pub fn set_option_read_observer(&mut self, observer: OptionReadObserver) {
        self.option_read_observer = Some(observer);
    }

    /// Selects an exact stock-Nix semantic compatibility profile.
    ///
    /// The reported `builtins.nixVersion` bytes are independent. Call
    /// [`Self::reset_reported_nix_version`] when they should follow the newly
    /// selected profile.
    pub fn set_nix_compat_profile(&mut self, profile: NixCompatProfile) {
        self.nix_compat_profile = profile;
    }

    /// Replaces the bytes exposed through `builtins.nixVersion`.
    ///
    /// This does not change the semantic compatibility profile.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError::EmptyReportedNixVersion`] when `version`
    /// is empty.
    pub fn set_reported_nix_version(
        &mut self,
        version: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        let version = version.into();
        if version.is_empty() {
            return Err(TreeWalkOptionsError::EmptyReportedNixVersion);
        }
        self.reported_nix_version = version;
        Ok(())
    }

    /// Resets `builtins.nixVersion` to the selected profile's stock version.
    pub fn reset_reported_nix_version(&mut self) {
        self.reported_nix_version = self.nix_compat_profile.stock_version().to_vec();
    }

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

    /// Creates evaluator options with a deterministic IR-node step budget.
    pub fn with_max_eval_steps(max_eval_steps: u64) -> Self {
        let mut options = Self::default();
        options.set_max_eval_steps(Some(max_eval_steps));
        options
    }

    /// Creates evaluator options with an in-engine wall-clock deadline.
    pub fn with_max_eval_duration(max_eval_duration: std::time::Duration) -> Self {
        let mut options = Self::default();
        options.set_max_eval_duration(Some(max_eval_duration));
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

    /// Creates evaluator options with a configured persistent-cache root.
    ///
    /// Ordinary filesystem-backed imports may lazily hydrate durable parse
    /// artifacts from this root, and may write back newly parsed import
    /// artifacts to it when [`Self::parse_cache_root`] is also configured.
    /// Forced-expression cache observation may also use this root for demand
    /// accounting, durable hit selection, and threshold-driven durable
    /// value/trace writeback when [`Self::eval_cache_enabled`] is true.
    pub fn with_persist_cache_root(persist_cache_root: impl Into<PathBuf>) -> Self {
        let mut options = Self::default();
        options.set_persist_cache_root(persist_cache_root);
        options
    }

    /// Creates evaluator options with advisory eval-cache observation configured.
    pub fn with_eval_cache_enabled(eval_cache_enabled: bool) -> Self {
        let mut options = Self::default();
        options.set_eval_cache_enabled(eval_cache_enabled);
        options
    }

    /// Creates evaluator options with durable force-cache materialization costs.
    pub fn with_force_cache_materialization_costs(costs: MaterializationCosts) -> Self {
        let mut options = Self::default();
        options.set_force_cache_materialization_costs(costs);
        options
    }

    /// Creates evaluator options with a configured high-water heap budget.
    pub fn with_heap_memory_budget(heap_memory_budget: HeapMemoryBudget) -> Self {
        let mut options = Self::default();
        options.set_heap_memory_budget(heap_memory_budget);
        options
    }

    /// Creates evaluator options with post-evaluation Tier-B admission configured.
    pub fn with_heap_tier_b_transition_admission_enabled(enabled: bool) -> Self {
        let mut options = Self::default();
        options.set_heap_tier_b_transition_admission_enabled(enabled);
        options
    }

    /// Creates evaluator options with opt-in thread-local Tier-A worker storage.
    pub fn with_heap_thread_local_tier_a_enabled(enabled: bool) -> Self {
        let mut options = Self::default();
        options.set_heap_thread_local_tier_a_enabled(enabled);
        options
    }

    /// Creates evaluator options with a GC-stress polling policy.
    pub fn with_gc_stress_policy(policy: GcStressPolicy) -> Self {
        let mut options = Self::default();
        options.set_gc_stress_policy(policy);
        options
    }

    /// Creates evaluator options with a configured thunk-resolution barrier tier.
    pub fn with_thunk_resolve_barrier_tier(tier: GenerationalGcTier) -> Self {
        let mut options = Self::default();
        options.set_thunk_resolve_barrier_tier(tier);
        options
    }

    /// Creates evaluator options with parallel thunk payload storage configured.
    pub fn with_parallel_thunk_payloads_enabled(enabled: bool) -> Self {
        let mut options = Self::default();
        options.set_parallel_thunk_payloads_enabled(enabled);
        options
    }

    /// Creates evaluator options with the active parallel thunk worker id.
    pub fn with_parallel_thunk_worker_id(worker_id: ParallelThunkWorkerId) -> Self {
        let mut options = Self::default();
        options.set_parallel_thunk_worker_id(worker_id);
        options
    }

    /// Creates evaluator options with parallel evaluation mode configured.
    pub fn with_parallel_workers(workers: Option<std::num::NonZeroUsize>) -> Self {
        let mut options = Self::default();
        options.set_parallel_workers(workers);
        options
    }

    /// Creates evaluator options with post-evaluation cheap heap advice for owned outcomes.
    pub fn with_heap_cheap_memory_advice_min_idle_epochs(min_idle_epochs: u64) -> Self {
        let mut options = Self::default();
        options.set_heap_cheap_memory_advice_min_idle_epochs(min_idle_epochs);
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

    /// Replaces the deterministic IR-node step budget.
    pub fn set_max_eval_steps(&mut self, max_eval_steps: Option<u64>) {
        self.max_eval_steps = max_eval_steps;
    }

    /// Replaces the in-engine wall-clock evaluation deadline.
    pub fn set_max_eval_duration(&mut self, max_eval_duration: Option<std::time::Duration>) {
        self.max_eval_duration = max_eval_duration;
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

    /// Replaces the hidden C++ Nix corepkgs directory used for `<nix/...>`.
    ///
    /// C++ Nix resolves some `<nix/...>` lookups from an internal corepkgs tree
    /// without reflecting that tree in `builtins.nixPath`. Setting this path
    /// models that fallback while keeping [`TreeWalkOptions::nix_path`] focused
    /// on visible search-path entries.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkOptionsError`] if `path` is relative.
    pub fn set_corepkgs_path(
        &mut self,
        path: impl Into<Vec<u8>>,
    ) -> Result<(), TreeWalkOptionsError> {
        self.corepkgs_path = Some(normalize_absolute_path(
            path.into(),
            b"/",
            TreeWalkOptionsError::RelativeCorepkgsPath,
        )?);
        Ok(())
    }

    /// Clears the hidden C++ Nix corepkgs directory.
    pub fn clear_corepkgs_path(&mut self) {
        self.corepkgs_path = None;
    }

    /// Enables or disables ambient Nix search-path lookup.
    ///
    /// When enabled outside pure evaluation, ambient `<...>` lookup and
    /// `builtins.nixPath` fail before observing configured search-path entries.
    /// A lexical `__nixPath` and explicit `builtins.findFile` lists remain
    /// evaluable because they do not read the ambient Nix search path. Pure
    /// evaluation already hides the ambient path, so it exposes an empty
    /// `builtins.nixPath` and ordinary missing `<...>` lookups.
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

    /// Replaces the persistent-cache root directory.
    ///
    /// This enables advisory durable import parse-cache hit lookup and
    /// writeback only when a normal parse-cache root is also configured,
    /// because hydrated artifacts are read back through the parse-cache entry
    /// layout before evaluation. It also supplies the persistent root for
    /// forced-expression demand accounting, durable hit selection, and
    /// threshold-driven value/trace writeback when eval-cache observation is
    /// enabled.
    pub fn set_persist_cache_root(&mut self, persist_cache_root: impl Into<PathBuf>) {
        self.persist_cache_root = Some(persist_cache_root.into());
    }

    /// Disables persistent-cache use by this evaluator.
    pub fn clear_persist_cache_root(&mut self) {
        self.persist_cache_root = None;
    }

    /// Enables or disables persistent value-decode content re-hashing.
    ///
    /// When disabled (the default), indexed value decoding trusts the
    /// content-address key and pack integrity header. When enabled, every
    /// decoded persistent value is re-hashed and must match its content address.
    /// This is wired to the `AOS_NIX_CACHE_VERIFY` knob for defensive
    /// verification of the persistent value store.
    pub fn set_persist_cache_verify(&mut self, persist_cache_verify: bool) {
        self.persist_cache_verify = persist_cache_verify;
    }

    /// Enables or disables advisory incremental eval-cache observation.
    ///
    /// This controls in-memory [`crate::cache::EvalCache`] observation and,
    /// when a persistent-cache root is configured, gates forced-expression
    /// demand accounting, durable hit selection, durable payload writeback, and
    /// verifying-trace writeback. It does not disable parse-cache persistence
    /// for callers that configure parse and persistent roots explicitly, and it
    /// does not enable the future full demand-graph evaluator or general memo
    /// lookup.
    pub fn set_eval_cache_enabled(&mut self, eval_cache_enabled: bool) {
        self.eval_cache_enabled = eval_cache_enabled;
    }

    /// Replaces the durable materialization costs for forced-expression payloads.
    pub fn set_force_cache_materialization_costs(&mut self, costs: MaterializationCosts) {
        self.force_cache_materialization_costs = costs;
    }

    /// Replaces the high-water heap budget for this evaluator.
    pub fn set_heap_memory_budget(&mut self, heap_memory_budget: HeapMemoryBudget) {
        self.heap_memory_budget = Some(heap_memory_budget);
    }

    /// Enables or disables fail-closed enforcement of the hard heap ceiling.
    pub fn set_enforce_heap_memory_budget(&mut self, enforce: bool) {
        self.enforce_heap_memory_budget = enforce;
    }

    /// Clears the high-water heap budget for this evaluator.
    pub fn clear_heap_memory_budget(&mut self) {
        self.heap_memory_budget = None;
    }

    /// Enables or disables automatic post-evaluation Tier-B admission.
    ///
    /// When enabled, owned evaluation outcomes whose final heap-budget action
    /// requested Tier B immediately apply the generation-metadata admission
    /// bridge before being returned to the caller. This does not install a
    /// collector, switch allocators, reserve semispace storage, rewrite
    /// handles, mutate object bodies, publish remembered/card state, or
    /// relocate values.
    pub fn set_heap_tier_b_transition_admission_enabled(&mut self, enabled: bool) {
        self.heap_tier_b_transition_admission_enabled = enabled;
    }

    /// Selects the record-table worker-closure placement (doc 30 FV-3).
    ///
    /// This is the Tier-B B2 proving ground's options-level admission door:
    /// generation-rewrite and record-relocation harnesses need worker
    /// closures allocated as record-table records instead of flat objects.
    /// Production never sets this; heaps running under a GC-stress policy or
    /// a generational write-barrier tier select the record placement
    /// automatically.
    pub fn set_record_worker_closures_for_gc_scaffolding(&mut self, enabled: bool) {
        self.record_worker_closures_for_gc_scaffolding = enabled;
    }

    /// Enables or disables thread-local Tier-A worker storage.
    ///
    /// When enabled, the tree-walk heap still uses the Tier-A one-shot
    /// allocation strategy and `aos_alloc_*` dispatch table, but worker
    /// allocations are stored in the current thread's arena instead of an
    /// evaluator-owned arena. This does not change permanent-shared storage,
    /// install Tier B, or make the thread-local backend the process-wide
    /// default.
    pub fn set_heap_thread_local_tier_a_enabled(&mut self, enabled: bool) {
        self.heap_thread_local_tier_a_enabled = enabled;
    }

    /// Enables or disables the default-off serial Apply-shaped typed-head experiment.
    pub fn set_typed_apply_thunk_heads_enabled(&mut self, enabled: bool) {
        self.typed_apply_thunk_heads_enabled = enabled;
    }

    /// Enables the serial active packed Apply/GenList experiment.
    #[cfg(feature = "active_packed_thunk_probe")]
    pub fn set_active_packed_thunk_capacities(&mut self, capacities: ActivePackedThunkCapacities) {
        self.active_packed_thunk_capacities = Some(capacities);
    }

    /// Disables the serial active packed Apply/GenList experiment.
    #[cfg(feature = "active_packed_thunk_probe")]
    pub fn clear_active_packed_thunk_capacities(&mut self) {
        self.active_packed_thunk_capacities = None;
    }

    /// Installs a GC-stress polling policy for evaluator heap allocations.
    pub fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.gc_stress_policy = policy;
    }

    /// Disables GC-stress polling for evaluator heap allocations.
    pub fn clear_gc_stress_policy(&mut self) {
        self.gc_stress_policy = GcStressPolicy::disabled();
    }

    /// Selects the Tier-B live-reclamation mode (the `AOS_NIX_GC` knob).
    ///
    /// `EvalGcMode::Sweep` enables thunk capture shedding at force publish and
    /// precise non-moving sweeps at evaluator quiescent points. The default
    /// `EvalGcMode::Off` keeps Tier-A never-free semantics. Parallel
    /// evaluation pins the effective mode to `Off` regardless of this setting.
    pub fn set_gc_mode(&mut self, mode: EvalGcMode) {
        self.gc_mode = mode;
    }

    /// Sets the worker-record growth required between Tier-B quiescent sweeps.
    pub fn set_gc_sweep_threshold(&mut self, threshold: u64) {
        self.gc_sweep_threshold = threshold;
    }

    /// Selects the generational tier used for thunk-resolution write barriers.
    pub fn set_thunk_resolve_barrier_tier(&mut self, tier: GenerationalGcTier) {
        self.thunk_resolve_barrier_tier = tier;
    }

    /// Enables or disables parallel payload cells on newly allocated thunks.
    ///
    /// This only admits storage for evaluator-native parallel forcing; the
    /// serial tree-walk force path remains authoritative until the parallel
    /// scheduler executes thunk bodies.
    pub fn set_parallel_thunk_payloads_enabled(&mut self, enabled: bool) {
        self.parallel_thunk_payloads_enabled = enabled;
    }

    /// Configures parallel evaluation mode with a target worker count.
    ///
    /// `Some(n)` turns parallel mode on: newly allocated thunks carry parallel
    /// payload cells bound to the evaluator's shared cycle registry, so `n`
    /// worker evaluators can force overlapping thunks of one shared demand
    /// graph through the claim/park protocol. `None` (the default) is the
    /// serial evaluator with zero thunk-storage overhead.
    ///
    /// The count records the requested fan-out for scheduler integration; a
    /// single evaluator running with `Some(n)` still forces serially with one
    /// worker id and produces identical results. Parallel mode also implies:
    ///
    /// - the tier-1 JIT engine is not installed (`AOS_NIX_JIT` is ignored);
    /// - minor GC stays quiesced: the production evaluator never runs minor
    ///   collections (arenas grow monotonically for the eval's lifetime), and
    ///   GC-stress polling must not be combined with parallel mode. Claimed
    ///   parallel cells refuse relocation writebacks, which turns any such
    ///   combination into an explicit error instead of a data race.
    pub fn set_parallel_workers(&mut self, workers: Option<std::num::NonZeroUsize>) {
        self.parallel_workers = workers;
    }

    /// Enables or disables hidden-class shape projection at `K >= 2`.
    ///
    /// See [`Self::parallel_shape_projection`] for the semantics and the
    /// measured rationale behind the `false` default.
    pub fn set_parallel_shape_projection(&mut self, enabled: bool) {
        self.parallel_shape_projection = enabled;
    }

    /// Replaces the hidden-class shape strategy for heap attrset records.
    ///
    /// See [`AttrShapeMode`] for the modes. The strategy is byte-neutral:
    /// it changes only how attrset selects and shape projection are served,
    /// never the produced values or `.drv` bytes.
    pub fn set_attr_shape_mode(&mut self, mode: AttrShapeMode) {
        self.attr_shape_mode = mode;
    }

    /// Enables or disables publishing promoted tier-1 native entries for dispatch.
    ///
    /// When disabled (the default), `publish_tier1_slot` is a no-op and installed
    /// tier-1 slots are never transitioned to `Published`, so the force path
    /// behaves identically to an evaluator with no side-table. The flag gates
    /// only the publish step; installing and looking up slots are unaffected.
    pub fn set_jit_tier1_publish_enabled(&mut self, enabled: bool) {
        self.jit_tier1_publish_enabled = enabled;
    }

    /// Replaces the active worker id used for parallel thunk sidecar claims.
    ///
    /// The id is observable only through the parallel thunk protocol. The
    /// default single-worker tree-walk evaluator uses
    /// [`ParallelThunkWorkerId::FIRST`]; scheduler integration will assign a
    /// distinct id per worker before entering the force path.
    pub fn set_parallel_thunk_worker_id(&mut self, worker_id: ParallelThunkWorkerId) {
        self.parallel_thunk_worker_id = worker_id;
    }

    /// Enables post-evaluation cheap heap advice for owned evaluation outcomes.
    pub fn set_heap_cheap_memory_advice_min_idle_epochs(&mut self, min_idle_epochs: u64) {
        self.heap_cheap_memory_advice_min_idle_epochs = Some(min_idle_epochs);
    }

    /// Disables post-evaluation cheap heap advice for owned evaluation outcomes.
    pub fn clear_heap_cheap_memory_advice(&mut self) {
        self.heap_cheap_memory_advice_min_idle_epochs = None;
    }

    /// Configures one exact indirect flake-reference resolution.
    ///
    /// The `indirect` key uses the same canonical string form returned by
    /// `builtins.flakeRefToString`, such as `flake:nixpkgs` or
    /// `flake:nixpkgs/unstable`. The `target` must be another flake reference
    /// string that either `builtins.fetchTree` already supports natively or
    /// another configured indirect ref. The evaluator never reads an ambient
    /// registry, so callers must install every deterministic mapping they want
    /// `flake:` refs to observe.
    pub fn set_flake_ref_resolution(
        &mut self,
        indirect: impl Into<Vec<u8>>,
        target: impl Into<Vec<u8>>,
    ) {
        self.flake_ref_resolutions
            .insert(indirect.into(), target.into());
    }

    /// Clears one configured indirect flake-reference resolution.
    pub fn clear_flake_ref_resolution(&mut self, indirect: &[u8]) {
        self.flake_ref_resolutions.remove(indirect);
    }

    /// Clears every configured indirect flake-reference resolution.
    pub fn clear_flake_ref_resolutions(&mut self) {
        self.flake_ref_resolutions.clear();
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

    pub fn path_is_allowed(&self, path: &[u8]) -> bool {
        self.allowed_paths
            .iter()
            .any(|allowed| path_is_under_root(path, allowed))
    }

    pub fn resolved_path_is_allowed(&self, path: &[u8]) -> bool {
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
}

/// Errors raised while configuring a tree-walk evaluator.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TreeWalkOptionsError {
    /// The configured `builtins.nixVersion` value is empty.
    #[error("reported Nix version must not be empty")]
    EmptyReportedNixVersion,
    /// The configured Nix store directory is not an absolute path.
    #[error("Nix store directory must be absolute")]
    RelativeStoreDir,

    /// The configured search-path base directory is not an absolute path.
    #[error("Nix search-path base directory must be absolute")]
    RelativeSearchPathBase,

    /// The configured path-literal base directory is not an absolute path.
    #[error("Nix path-literal base directory must be absolute")]
    RelativePathLiteralBase,

    /// The configured corepkgs directory is not an absolute path.
    #[error("Nix corepkgs directory must be absolute")]
    RelativeCorepkgsPath,

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

mod option_queries;
