//! Recording of impure evaluator input observations for future cache leaves.

use super::*;

impl TreeWalk {
    pub(super) fn impure_input_trace_cursor(&self) -> ImpureInputTraceCursor {
        ImpureInputTraceCursor {
            len: self.impure_input_trace.len(),
            complete: self.impure_input_trace_complete,
            force_cache_epoch: self.force_cache_impure_trace_epoch,
        }
    }

    pub(super) fn impure_input_trace_segment(
        &self,
        cursor: ImpureInputTraceCursor,
    ) -> ImpureInputTraceSegment {
        if !cursor.complete || !self.impure_input_trace_complete {
            return ImpureInputTraceSegment {
                trace: Vec::new(),
                complete: false,
            };
        }
        let Some(trace) = self.impure_input_trace.get(cursor.len..) else {
            return ImpureInputTraceSegment {
                trace: Vec::new(),
                complete: false,
            };
        };
        ImpureInputTraceSegment {
            trace: trace.to_vec(),
            complete: true,
        }
    }

    pub(super) fn force_cache_impure_input_trace_segment(
        &self,
        cursor: ImpureInputTraceCursor,
    ) -> ImpureInputTraceSegment {
        let mut segment = self.impure_input_trace_segment(cursor);
        if cursor.force_cache_epoch != self.force_cache_impure_trace_epoch {
            segment.complete = false;
        }
        segment
    }

    pub(super) fn record_impure_input_result(
        &mut self,
        fingerprint: Result<ImpureInputFingerprint, InputFingerprintError>,
    ) {
        let Ok(fingerprint) = fingerprint else {
            self.mark_impure_input_trace_incomplete();
            return;
        };
        self.record_impure_input(fingerprint);
    }

    pub(super) fn record_impure_input(&mut self, fingerprint: ImpureInputFingerprint) {
        if !self.impure_input_trace_complete {
            return;
        }
        if self.impure_input_trace.try_reserve_exact(1).is_err() {
            self.mark_impure_input_trace_incomplete();
            return;
        }
        self.impure_input_trace.push(fingerprint);
    }

    pub(super) fn mark_impure_input_trace_incomplete(&mut self) {
        self.impure_input_trace.clear();
        self.impure_input_trace_complete = false;
    }

    pub(super) fn mark_force_cache_impure_input_trace_incomplete(&mut self) {
        self.force_cache_impure_trace_epoch = self.force_cache_impure_trace_epoch.wrapping_add(1);
    }

    pub(super) fn file_type_for_impure_input(file_type: fs::FileType) -> FileTypeForInput {
        if file_type.is_file() {
            FileTypeForInput::Regular
        } else if file_type.is_dir() {
            FileTypeForInput::Directory
        } else if file_type.is_symlink() {
            FileTypeForInput::Symlink
        } else {
            FileTypeForInput::Unknown
        }
    }
}

/// Re-observes a recorded impure-input trace under the current filesystem state.
///
/// Each fingerprint's identity is replayed through a
/// [`TreeWalkImpureInputRevalidator`] built from `options` and its freshly
/// observed result hash is compared against the recorded one. The function
/// returns `true` only when every input still observes an identical result;
/// any changed input, un-revalidatable identity (for example a path that is no
/// longer allowed or readable), or empty-vs-present mismatch returns `false`.
///
/// This is the `O(inputs)` validation used by root-level early cutoff to decide
/// whether a durable derivation-closure record may be re-emitted without
/// re-evaluating the expression.
pub fn revalidate_cacheable_input_trace(
    options: &TreeWalkOptions,
    trace: &[crate::cache::CacheableInputFingerprint],
) -> bool {
    let mut revalidator = TreeWalkImpureInputRevalidator::new(options);
    trace.iter().all(
        |recorded| match revalidator.revalidate_impure_input(recorded.identity()) {
            Some(observed) => observed
                .as_cacheable()
                .is_some_and(|observed| observed.observation_hash() == recorded.observation_hash()),
            None => false,
        },
    )
}

impl<'a> TreeWalkImpureInputRevalidator<'a> {
    pub(super) fn new(options: &'a TreeWalkOptions) -> Self {
        Self {
            options,
            trace: Vec::new(),
        }
    }

    pub(super) fn into_revalidated_trace(self) -> Vec<ImpureInputFingerprint> {
        self.trace
    }

    fn remember(&mut self, fingerprint: ImpureInputFingerprint) -> Option<ImpureInputFingerprint> {
        self.trace.try_reserve_exact(1).ok()?;
        self.trace.push(fingerprint.clone());
        Some(fingerprint)
    }

    fn filesystem_path_is_allowed(&self, path: &[u8]) -> bool {
        if self.options.eval_mode() == EvalMode::Impure {
            return true;
        }
        if !Path::new(OsStr::from_bytes(path)).is_absolute() {
            return false;
        }
        let normalized = normalize_absolute_path_bytes(path);
        if !self.options.path_is_allowed(&normalized) {
            return false;
        }
        canonicalize_policy_path(path)
            .is_none_or(|resolved| self.options.resolved_path_is_allowed(&resolved))
    }

    fn revalidate_import(&self, identity: &ImpureInputIdentity) -> Option<ImpureInputFingerprint> {
        let path = identity.subject();
        if !self.filesystem_path_is_allowed(path) {
            return None;
        }
        let source = fs::read(Path::new(OsStr::from_bytes(path))).ok()?;
        ImpureInputFingerprint::import(path, &source).ok()
    }

    fn revalidate_read_file(
        &self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint> {
        let path = identity.subject();
        if !self.filesystem_path_is_allowed(path) {
            return None;
        }
        let contents = fs::read(Path::new(OsStr::from_bytes(path))).ok()?;
        if contents.contains(&0) {
            return None;
        }
        ImpureInputFingerprint::read_file(path, &contents).ok()
    }

    fn revalidate_hash_file(
        &self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint> {
        let path = identity.subject();
        if !self.filesystem_path_is_allowed(path) {
            return None;
        }
        let contents = fs::read(Path::new(OsStr::from_bytes(path))).ok()?;
        ImpureInputFingerprint::hash_file(path, &contents).ok()
    }

    fn revalidate_read_dir(
        &self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint> {
        let path = identity.subject();
        if !self.filesystem_path_is_allowed(path) {
            return None;
        }
        let entries = fs::read_dir(Path::new(OsStr::from_bytes(path))).ok()?;
        let mut trace_entries = Vec::new();
        for entry in entries {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let file_type = entry.file_type().ok()?;
            let name = name.as_bytes();
            let mut trace_name = Vec::new();
            trace_name.try_reserve_exact(name.len()).ok()?;
            trace_name.extend_from_slice(name);
            trace_entries.try_reserve_exact(1).ok()?;
            trace_entries.push((trace_name, TreeWalk::file_type_for_impure_input(file_type)));
        }
        ImpureInputFingerprint::read_dir(
            path,
            trace_entries
                .iter()
                .map(|(name, file_type)| DirEntryInput::new(name.as_slice(), *file_type)),
        )
        .ok()
    }

    fn revalidate_read_file_type(
        &self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint> {
        let path = identity.subject();
        if !self.filesystem_path_is_allowed(path) {
            return None;
        }
        let stat_path = path_without_trailing_path_markers(path);
        let file_type = fs::symlink_metadata(Path::new(OsStr::from_bytes(stat_path)))
            .ok()?
            .file_type();
        ImpureInputFingerprint::read_file_type(
            path,
            TreeWalk::file_type_for_impure_input(file_type),
        )
        .ok()
    }

    fn revalidate_path_exists(
        &self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint> {
        let path = identity.subject();
        if !self.filesystem_path_is_allowed(path) {
            return None;
        }
        let (metadata, must_be_dir) = match identity.mode() {
            ImpureInputMode::Default => (
                fs::symlink_metadata(Path::new(OsStr::from_bytes(
                    path_without_trailing_path_markers(path),
                ))),
                false,
            ),
            ImpureInputMode::RequireDirectory => {
                (fs::metadata(Path::new(OsStr::from_bytes(path))), true)
            }
            ImpureInputMode::FindFileCandidate => {
                (fs::metadata(Path::new(OsStr::from_bytes(path))), false)
            }
        };
        let exists = match metadata {
            Ok(metadata) => !must_be_dir || metadata.is_dir(),
            Err(source)
                if matches!(
                    source.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                false
            }
            Err(_) => return None,
        };
        ImpureInputFingerprint::path_exists_with_mode(path, identity.mode(), exists).ok()
    }

    fn revalidate_get_env(&self, identity: &ImpureInputIdentity) -> Option<ImpureInputFingerprint> {
        if self.options.eval_mode() == EvalMode::Pure {
            return None;
        }
        let name = identity.subject();
        ImpureInputFingerprint::get_env(name, self.options.env_var(name)).ok()
    }
}

impl ImpureInputRevalidator for TreeWalkImpureInputRevalidator<'_> {
    fn revalidate_impure_input(
        &mut self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint> {
        let fingerprint = match identity.kind() {
            ImpureInputKind::Import => self.revalidate_import(identity),
            ImpureInputKind::ReadFile => self.revalidate_read_file(identity),
            ImpureInputKind::HashFile => self.revalidate_hash_file(identity),
            ImpureInputKind::ReadDir => self.revalidate_read_dir(identity),
            ImpureInputKind::ReadFileType => self.revalidate_read_file_type(identity),
            ImpureInputKind::PathExists => self.revalidate_path_exists(identity),
            ImpureInputKind::GetEnv => self.revalidate_get_env(identity),
        }?;
        self.remember(fingerprint)
    }
}
