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

/// Canonicalizes a complete cacheable impure-input trace for durable recording.
///
/// The evaluator appends impure-input observations in force order, so two
/// evaluations of the same expression may record the same set of observations
/// in different orders (parallel evaluation makes force order
/// nondeterministic). This function makes the recorded form order-independent
/// without changing observation semantics: entries are sorted by input kind,
/// mode, identity subject, and observation hash, and duplicate observations of
/// the same input with identical results collapse to one entry.
///
/// Returns `None` when the same input identity was observed with two different
/// results within one evaluation (for example a file that changed mid-eval).
/// Such a trace can never revalidate — one replay of the input cannot match
/// both recorded results — so callers must treat it exactly like an incomplete
/// trace and record nothing.
///
/// Per-observation replay through [`revalidate_cacheable_input_trace`] checks
/// each input independently, so canonicalization never changes revalidation
/// outcomes.
pub fn canonicalize_cacheable_input_trace(
    mut trace: Vec<crate::cache::CacheableInputFingerprint>,
) -> Option<Vec<crate::cache::CacheableInputFingerprint>> {
    trace.sort_by(canonical_cacheable_input_order);
    trace.dedup();
    // After sorting, observations that share an identity are adjacent; any
    // surviving adjacent pair with equal identity must differ in observed
    // result, which makes the trace unsafe to record.
    let conflicting = trace.windows(2).any(|adjacent| {
        adjacent[0].identity() == adjacent[1].identity()
            && adjacent[0].observation_hash() != adjacent[1].observation_hash()
    });
    if conflicting { None } else { Some(trace) }
}

/// Orders cacheable inputs by kind, mode, identity subject, then observation
/// hash, grouping observations of the same identity adjacently.
fn canonical_cacheable_input_order(
    left: &crate::cache::CacheableInputFingerprint,
    right: &crate::cache::CacheableInputFingerprint,
) -> std::cmp::Ordering {
    (
        left.kind(),
        left.identity().mode(),
        left.identity().subject(),
        left.observation_hash(),
    )
        .cmp(&(
            right.kind(),
            right.identity().mode(),
            right.identity().subject(),
            right.observation_hash(),
        ))
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

#[cfg(test)]
mod canonicalize_tests {
    use super::canonicalize_cacheable_input_trace;
    use crate::cache::{
        CacheableInputFingerprint, ImpureInputFingerprint, ImpureInputMode, RootInstantiationRecord,
    };

    fn cacheable(fingerprint: ImpureInputFingerprint) -> CacheableInputFingerprint {
        fingerprint
            .as_cacheable()
            .expect("input is cacheable")
            .clone()
    }

    fn sample_observations() -> Vec<CacheableInputFingerprint> {
        vec![
            cacheable(ImpureInputFingerprint::import(b"/src/default.nix", b"{ }").expect("hashes")),
            cacheable(ImpureInputFingerprint::read_file(b"/src/data", b"payload").expect("hashes")),
            cacheable(
                ImpureInputFingerprint::get_env(b"HOME", Some(b"/home/user")).expect("hashes"),
            ),
            cacheable(ImpureInputFingerprint::path_exists(b"/src/opt", false).expect("hashes")),
        ]
    }

    #[test]
    fn canonical_trace_is_order_independent() {
        let forward =
            canonicalize_cacheable_input_trace(sample_observations()).expect("no conflicts");
        let mut shuffled_input = sample_observations();
        shuffled_input.reverse();
        shuffled_input.swap(0, 2);
        let shuffled =
            canonicalize_cacheable_input_trace(shuffled_input).expect("no conflicts");
        assert_eq!(forward, shuffled);
    }

    #[test]
    fn canonical_traces_encode_identical_root_records() {
        let forward =
            canonicalize_cacheable_input_trace(sample_observations()).expect("no conflicts");
        let mut reversed_input = sample_observations();
        reversed_input.reverse();
        let reversed =
            canonicalize_cacheable_input_trace(reversed_input).expect("no conflicts");

        let record = |inputs| {
            RootInstantiationRecord::new(b"/nix/store/root.drv".to_vec(), Vec::new(), inputs, 7)
                .encode()
                .expect("record encodes")
        };
        assert_eq!(record(forward), record(reversed));
    }

    #[test]
    fn identical_duplicate_observations_collapse() {
        let repeated = cacheable(
            ImpureInputFingerprint::read_file(b"/src/data", b"payload").expect("hashes"),
        );
        let canonical =
            canonicalize_cacheable_input_trace(vec![repeated.clone(), repeated.clone()])
                .expect("no conflicts");
        assert_eq!(canonical, vec![repeated]);
    }

    #[test]
    fn conflicting_duplicate_observation_refuses_to_canonicalize() {
        let before =
            cacheable(ImpureInputFingerprint::read_file(b"/src/data", b"before").expect("hashes"));
        let after =
            cacheable(ImpureInputFingerprint::read_file(b"/src/data", b"after").expect("hashes"));
        assert_eq!(canonicalize_cacheable_input_trace(vec![before, after]), None);
    }

    #[test]
    fn distinct_modes_on_one_subject_are_not_conflicts() {
        let default_probe =
            cacheable(ImpureInputFingerprint::path_exists(b"/src/opt", true).expect("hashes"));
        let directory_probe = cacheable(
            ImpureInputFingerprint::path_exists_with_mode(
                b"/src/opt",
                ImpureInputMode::RequireDirectory,
                false,
            )
            .expect("hashes"),
        );
        let canonical =
            canonicalize_cacheable_input_trace(vec![directory_probe, default_probe])
                .expect("no conflicts");
        assert_eq!(canonical.len(), 2);
    }
}
