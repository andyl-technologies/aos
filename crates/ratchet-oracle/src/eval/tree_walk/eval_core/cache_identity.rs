//! Force-cache identity hashing over evaluator options.
//!
//! Folds every option that changes observable evaluation semantics into the
//! [`ForceCacheOptionsIdentity`] domain hashes so cached force payloads from
//! a differently-configured evaluator can never collide.

use super::*;
use crate::cache::hashing::CacheDigestHasher;

impl ForceCacheOptionsIdentity {
    pub(super) fn new(options: &TreeWalkOptions) -> Self {
        Self {
            nix_compat_profile: options.nix_compat_profile(),
            reported_nix_version: options.reported_nix_version().to_vec(),
            store_dir: options.store_dir().to_vec(),
            search_path_base: options.search_path_base().to_vec(),
            nix_path: options.nix_path().to_vec(),
            corepkgs_path: options.corepkgs_path().map(<[u8]>::to_vec),
            allowed_paths: options.allowed_paths().to_vec(),
            allowed_uris: options.allowed_uris().to_vec(),
            home_dir: options.home_dir().map(<[u8]>::to_vec),
            current_system: options.current_system().map(<[u8]>::to_vec),
            current_time: options.current_time(),
            eval_mode: options.eval_mode(),
            reject_ambient_search_path: options.reject_ambient_search_path(),
            reject_unconfigured_impure_builtin_constants: options
                .reject_unconfigured_impure_builtin_constants(),
        }
    }

    pub(super) fn update_cache_identity(&self, hasher: &mut CacheDigestHasher) -> Option<()> {
        hasher.update(b"force-cache-options-v5");
        hasher.update(b"nix-compat-profile");
        hasher.update(self.nix_compat_profile.cache_identity_bytes());
        hasher.update(b"reported-nix-version");
        TreeWalk::update_cache_identity_chunk(hasher, &self.reported_nix_version)?;
        hasher.update(b"store-dir");
        TreeWalk::update_cache_identity_chunk(hasher, &self.store_dir)?;
        hasher.update(b"search-path-base");
        TreeWalk::update_cache_identity_chunk(hasher, &self.search_path_base)?;
        hasher.update(b"nix-path");
        let nix_path_len = u64::try_from(self.nix_path.len()).ok()?;
        hasher.update(&nix_path_len.to_le_bytes());
        for entry in &self.nix_path {
            hasher.update(b"entry-prefix");
            TreeWalk::update_cache_identity_chunk(hasher, entry.prefix())?;
            hasher.update(b"entry-path");
            TreeWalk::update_cache_identity_chunk(hasher, entry.path())?;
        }
        match &self.corepkgs_path {
            Some(corepkgs_path) => {
                hasher.update(b"corepkgs-path");
                TreeWalk::update_cache_identity_chunk(hasher, corepkgs_path)?;
            }
            None => {
                hasher.update(b"no-corepkgs-path");
            }
        }
        hasher.update(b"allowed-paths");
        let allowed_paths_len = u64::try_from(self.allowed_paths.len()).ok()?;
        hasher.update(&allowed_paths_len.to_le_bytes());
        for path in &self.allowed_paths {
            hasher.update(b"allowed-path");
            TreeWalk::update_cache_identity_chunk(hasher, path)?;
        }
        hasher.update(b"allowed-uris");
        let allowed_uris_len = u64::try_from(self.allowed_uris.len()).ok()?;
        hasher.update(&allowed_uris_len.to_le_bytes());
        for uri in &self.allowed_uris {
            hasher.update(b"allowed-uri");
            TreeWalk::update_cache_identity_chunk(hasher, uri)?;
        }
        match &self.home_dir {
            Some(home_dir) => {
                hasher.update(b"home-dir");
                TreeWalk::update_cache_identity_chunk(hasher, home_dir)?;
            }
            None => {
                hasher.update(b"no-home-dir");
            }
        }
        match &self.current_system {
            Some(current_system) => {
                hasher.update(b"current-system");
                TreeWalk::update_cache_identity_chunk(hasher, current_system)?;
            }
            None => {
                hasher.update(b"no-current-system");
            }
        }
        match self.current_time {
            Some(current_time) => {
                hasher.update(b"current-time");
                hasher.update(&current_time.to_le_bytes());
            }
            None => {
                hasher.update(b"no-current-time");
            }
        }
        hasher.update(b"eval-mode");
        hasher.update(self.eval_mode_cache_identity_bytes());
        hasher.update(b"reject-ambient-search-path");
        hasher.update(&[u8::from(self.reject_ambient_search_path)]);
        hasher.update(b"reject-unconfigured-impure-builtin-constants");
        hasher.update(&[u8::from(self.reject_unconfigured_impure_builtin_constants)]);
        Some(())
    }

    const fn eval_mode_cache_identity_bytes(&self) -> &'static [u8] {
        match self.eval_mode {
            EvalMode::Impure => b"impure",
            EvalMode::Restricted => b"restricted",
            EvalMode::Pure => b"pure",
        }
    }

    pub(super) fn update_synthetic_builtin_cache_identity(
        &self,
        hasher: &mut CacheDigestHasher,
        execution: BuiltinExecution,
    ) -> Option<()> {
        hasher.update(b"force-cache-synthetic-builtin-options-v1");
        match execution {
            BuiltinExecution::TrueValue
            | BuiltinExecution::FalseValue
            | BuiltinExecution::NullValue => {
                hasher.update(b"no-option-dependencies");
            }
            BuiltinExecution::NixVersionValue => {
                hasher.update(b"nix-version");
                hasher.update(self.nix_compat_profile.cache_identity_bytes());
                TreeWalk::update_cache_identity_chunk(hasher, &self.reported_nix_version)?;
            }
            BuiltinExecution::LangVersionValue => {
                hasher.update(b"lang-version");
                hasher.update(&self.nix_compat_profile.lang_version().to_le_bytes());
            }
            BuiltinExecution::CurrentSystemValue => {
                hasher.update(b"current-system");
                self.update_synthetic_impure_constant_cache_identity(
                    hasher,
                    b"current-system-value",
                    self.current_system.as_deref(),
                )?;
            }
            BuiltinExecution::CurrentTimeValue => {
                hasher.update(b"current-time");
                let visible = self.eval_mode != EvalMode::Pure;
                if visible {
                    hasher.update(b"impure-constant-visible");
                } else {
                    hasher.update(b"impure-constant-hidden");
                }
                if visible {
                    match self.current_time {
                        Some(current_time) => {
                            hasher.update(b"current-time-value");
                            hasher.update(&current_time.to_le_bytes());
                        }
                        None => {
                            hasher.update(b"no-current-time-value");
                            hasher.update(b"reject-unconfigured-impure-builtin-constants");
                            hasher.update(&[u8::from(
                                self.reject_unconfigured_impure_builtin_constants,
                            )]);
                        }
                    }
                } else {
                    hasher.update(b"reject-unconfigured-impure-builtin-constants");
                    hasher.update(&[u8::from(self.reject_unconfigured_impure_builtin_constants)]);
                }
            }
            BuiltinExecution::StoreDirValue => {
                hasher.update(b"store-dir");
                TreeWalk::update_cache_identity_chunk(hasher, &self.store_dir)?;
            }
            BuiltinExecution::NixPathValue => {
                hasher.update(b"nix-path");
                hasher.update(b"reject-ambient-search-path");
                hasher.update(&[u8::from(self.reject_ambient_search_path)]);
                if self.reject_ambient_search_path {
                    return Some(());
                }
                let visible = self.eval_mode != EvalMode::Pure;
                if visible {
                    hasher.update(b"nix-path-visible");
                } else {
                    hasher.update(b"nix-path-hidden");
                }
                if !visible {
                    return Some(());
                }
                let nix_path_len = u64::try_from(self.nix_path.len()).ok()?;
                hasher.update(&nix_path_len.to_le_bytes());
                for entry in &self.nix_path {
                    hasher.update(b"entry-prefix");
                    TreeWalk::update_cache_identity_chunk(hasher, entry.prefix())?;
                    hasher.update(b"entry-path");
                    TreeWalk::update_cache_identity_chunk(hasher, entry.path())?;
                }
            }
            _ => {
                return None;
            }
        }
        Some(())
    }

    pub(super) fn update_first_class_primop_cache_identity(
        &self,
        hasher: &mut CacheDigestHasher,
        execution: BuiltinExecution,
    ) -> Option<()> {
        hasher.update(b"force-cache-first-class-primop-options-v1");
        match execution {
            BuiltinExecution::StrictUnary {
                primop: StrictUnaryPrimOp::GetEnv,
                ..
            } => {
                hasher.update(b"get-env");
                if self.eval_mode == EvalMode::Pure {
                    hasher.update(b"env-hidden");
                } else {
                    hasher.update(b"env-visible");
                }
            }
            _ => {
                return None;
            }
        }
        Some(())
    }

    pub(super) fn update_synthetic_impure_constant_cache_identity(
        &self,
        hasher: &mut CacheDigestHasher,
        value_label: &'static [u8],
        value: Option<&[u8]>,
    ) -> Option<()> {
        let visible = self.eval_mode != EvalMode::Pure;
        if visible {
            hasher.update(b"impure-constant-visible");
        } else {
            hasher.update(b"impure-constant-hidden");
        }
        if visible {
            match value {
                Some(value) => {
                    hasher.update(value_label);
                    TreeWalk::update_cache_identity_chunk(hasher, value)?;
                }
                None => {
                    hasher.update(b"no-impure-constant-value");
                    hasher.update(b"reject-unconfigured-impure-builtin-constants");
                    hasher.update(&[u8::from(self.reject_unconfigured_impure_builtin_constants)]);
                }
            }
        } else {
            hasher.update(b"reject-unconfigured-impure-builtin-constants");
            hasher.update(&[u8::from(self.reject_unconfigured_impure_builtin_constants)]);
        }
        Some(())
    }
}
