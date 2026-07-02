//! Parallel output collation precursors.
//!
//! This module owns the deterministic collation boundary that the future
//! parallel evaluator must preserve after tasks complete in nondeterministic
//! order. It models three RFC-0007 output rules before the real scheduler is
//! wired in:
//!
//! ```text
//! worker fragments -> stable task order
//! string contexts  -> order-independent canonical union
//! .drv outputs     -> path-sorted collection with content-only SHA-256 hashes
//! ```
//!
//! The implementation is a planning and test surface. It does not execute
//! thunks, materialize derivations, iterate live attrsets, or run the final
//! thread-count differential harness.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::string::{NixStringError, StringContext};

/// Collates worker-emitted output fragments into canonical output order.
///
/// Fragments are sorted by stable top-level task index before collation.
/// Duplicate task fragments are rejected because the L1 scheduler contract is
/// one visible result per task. String contexts are merged with
/// [`StringContext::union`], and `.drv` outputs are collected by path in
/// lexicographic order. Repeated `.drv` paths with identical bytes converge to
/// one output; repeated paths with different bytes are reported as conflicts.
///
/// # Errors
///
/// Returns [`ParallelOutputDeterminismError::DuplicateTaskFragment`] when more
/// than one fragment has the same task index. Returns
/// [`ParallelOutputDeterminismError::ConflictingDrvOutput`] when the same `.drv`
/// path is emitted with different bytes. Returns
/// [`ParallelOutputDeterminismError::StringContext`] if context union fails.
pub fn collate_parallel_output_fragments<I>(
    fragments: I,
) -> Result<ParallelOutputCollation, ParallelOutputDeterminismError>
where
    I: IntoIterator<Item = ParallelOutputFragment>,
{
    let mut ordered_fragments = fragments.into_iter().collect::<Vec<_>>();
    ordered_fragments.sort_by_key(ParallelOutputFragment::task_index);

    for pair in ordered_fragments.windows(2) {
        if pair[0].task_index == pair[1].task_index {
            return Err(ParallelOutputDeterminismError::DuplicateTaskFragment {
                task_index: pair[0].task_index,
            });
        }
    }

    let fragment_count = ordered_fragments.len();
    let mut string_context = StringContext::empty();
    let mut drv_outputs = BTreeMap::<Vec<u8>, ParallelDrvOutput>::new();

    for fragment in ordered_fragments {
        string_context = string_context.union(&fragment.string_context)?;
        for output in fragment.drv_outputs {
            let Some(existing) = drv_outputs.get(output.path()) else {
                drv_outputs.insert(output.path.clone(), output);
                continue;
            };
            if existing.bytes() != output.bytes() {
                return Err(ParallelOutputDeterminismError::ConflictingDrvOutput {
                    path: output.path,
                    existing_sha256: existing.content_sha256,
                    incoming_sha256: output.content_sha256,
                });
            }
        }
    }

    Ok(ParallelOutputCollation {
        fragment_count,
        string_context,
        drv_outputs: drv_outputs.into_values().collect(),
    })
}

/// Computes the content-only SHA-256 digest for `.drv` output bytes.
pub fn parallel_drv_output_content_sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut fixed = [0_u8; 32];
    fixed.copy_from_slice(&digest);
    fixed
}

/// One output fragment emitted after a top-level task completes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelOutputFragment {
    task_index: usize,
    worker_id: usize,
    string_context: StringContext,
    drv_outputs: Vec<ParallelDrvOutput>,
}

impl ParallelOutputFragment {
    /// Builds one worker-emitted output fragment.
    pub fn new(
        task_index: usize,
        worker_id: usize,
        string_context: StringContext,
        drv_outputs: Vec<ParallelDrvOutput>,
    ) -> Self {
        Self {
            task_index,
            worker_id,
            string_context,
            drv_outputs,
        }
    }

    /// Returns the stable top-level task index.
    pub const fn task_index(&self) -> usize {
        self.task_index
    }

    /// Returns the worker that emitted this fragment.
    pub const fn worker_id(&self) -> usize {
        self.worker_id
    }

    /// Returns the string context contributed by this fragment.
    pub const fn string_context(&self) -> &StringContext {
        &self.string_context
    }

    /// Returns `.drv` outputs contributed by this fragment.
    pub fn drv_outputs(&self) -> &[ParallelDrvOutput] {
        &self.drv_outputs
    }
}

/// One materialized `.drv` output candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelDrvOutput {
    path: Vec<u8>,
    bytes: Vec<u8>,
    content_sha256: [u8; 32],
}

impl ParallelDrvOutput {
    /// Creates a `.drv` output candidate and hashes its bytes.
    ///
    /// This precursor only validates that a path is present. Store-path syntax
    /// and the `.drv` suffix remain caller-owned invariants until this boundary
    /// is wired to derivation materialization.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelOutputDeterminismError::EmptyDrvOutputPath`] when
    /// `path` is empty.
    pub fn try_new(path: Vec<u8>, bytes: Vec<u8>) -> Result<Self, ParallelOutputDeterminismError> {
        if path.is_empty() {
            return Err(ParallelOutputDeterminismError::EmptyDrvOutputPath);
        }
        let content_sha256 = parallel_drv_output_content_sha256(&bytes);
        Ok(Self {
            path,
            bytes,
            content_sha256,
        })
    }

    /// Returns the raw `.drv` path bytes.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the materialized `.drv` bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the content-only SHA-256 digest of [`Self::bytes`].
    pub const fn content_sha256(&self) -> [u8; 32] {
        self.content_sha256
    }
}

/// Canonical output state after parallel fragment collation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParallelOutputCollation {
    fragment_count: usize,
    string_context: StringContext,
    drv_outputs: Vec<ParallelDrvOutput>,
}

impl ParallelOutputCollation {
    /// Returns how many fragments were accepted.
    pub const fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Returns the order-independent union of all fragment string contexts.
    pub const fn string_context(&self) -> &StringContext {
        &self.string_context
    }

    /// Returns `.drv` outputs in lexicographic path order.
    pub fn drv_outputs(&self) -> &[ParallelDrvOutput] {
        &self.drv_outputs
    }

    /// Returns the number of unique `.drv` output paths.
    pub fn drv_output_count(&self) -> usize {
        self.drv_outputs.len()
    }
}

/// A failure while collating parallel output fragments.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParallelOutputDeterminismError {
    /// More than one fragment was emitted for the same top-level task.
    #[error("parallel output fragment for task {task_index} was emitted more than once")]
    DuplicateTaskFragment {
        /// The duplicated task index.
        task_index: usize,
    },
    /// A `.drv` output path was empty.
    #[error("parallel drv output path is empty")]
    EmptyDrvOutputPath,
    /// The same `.drv` path was emitted with different content bytes.
    #[error("parallel drv output path {path:?} was emitted with conflicting bytes")]
    ConflictingDrvOutput {
        /// The conflicting `.drv` path bytes.
        path: Vec<u8>,
        /// The SHA-256 digest of the first bytes seen for this path.
        existing_sha256: [u8; 32],
        /// The SHA-256 digest of the later conflicting bytes.
        incoming_sha256: [u8; 32],
    },
    /// String context union failed.
    #[error(transparent)]
    StringContext(#[from] NixStringError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::ContextElement;

    fn opaque(path: &[u8]) -> ContextElement {
        ContextElement::opaque_path(path.to_vec()).expect("opaque context builds")
    }

    fn output(path: &[u8], name: &[u8]) -> ContextElement {
        ContextElement::single_output(path.to_vec(), name.to_vec()).expect("output context builds")
    }

    fn deep(path: &[u8]) -> ContextElement {
        ContextElement::deep_derivation(path.to_vec()).expect("deep context builds")
    }

    fn context(elements: Vec<ContextElement>) -> StringContext {
        StringContext::new(elements)
    }

    fn drv(path: &[u8], bytes: &[u8]) -> ParallelDrvOutput {
        ParallelDrvOutput::try_new(path.to_vec(), bytes.to_vec()).expect("drv output builds")
    }

    fn fragment(
        task_index: usize,
        worker_id: usize,
        string_context: StringContext,
        drv_outputs: Vec<ParallelDrvOutput>,
    ) -> ParallelOutputFragment {
        ParallelOutputFragment::new(task_index, worker_id, string_context, drv_outputs)
    }

    #[test]
    fn collation_is_independent_of_fragment_completion_order() {
        let source = opaque(b"/nix/store/aaa-source");
        let dep = output(b"/nix/store/bbb-pkg.drv", b"out");
        let toolchain = deep(b"/nix/store/ccc-toolchain.drv");

        let first = collate_parallel_output_fragments([
            fragment(
                2,
                0,
                context(vec![toolchain.clone()]),
                vec![drv(b"/nix/store/zzz-third.drv", b"third")],
            ),
            fragment(
                0,
                1,
                context(vec![source.clone(), dep.clone()]),
                vec![drv(b"/nix/store/aaa-first.drv", b"first")],
            ),
            fragment(
                1,
                0,
                context(vec![dep.clone()]),
                vec![drv(b"/nix/store/zzz-third.drv", b"third")],
            ),
        ])
        .expect("first collation succeeds");
        let second = collate_parallel_output_fragments([
            fragment(
                1,
                0,
                context(vec![dep.clone()]),
                vec![drv(b"/nix/store/zzz-third.drv", b"third")],
            ),
            fragment(
                2,
                0,
                context(vec![toolchain.clone()]),
                vec![drv(b"/nix/store/zzz-third.drv", b"third")],
            ),
            fragment(
                0,
                1,
                context(vec![source.clone(), dep.clone()]),
                vec![drv(b"/nix/store/aaa-first.drv", b"first")],
            ),
        ])
        .expect("second collation succeeds");

        assert_eq!(first, second);
        assert_eq!(first.fragment_count(), 3);
        assert_eq!(first.string_context().elements(), &[source, dep, toolchain]);
        assert_eq!(first.drv_output_count(), 2);
        assert_eq!(
            first
                .drv_outputs()
                .iter()
                .map(ParallelDrvOutput::path)
                .collect::<Vec<_>>(),
            vec![
                b"/nix/store/aaa-first.drv".as_slice(),
                b"/nix/store/zzz-third.drv".as_slice()
            ]
        );
    }

    #[test]
    fn drv_output_hashes_depend_only_on_content_bytes() {
        let left = drv(b"/nix/store/aaa-left.drv", b"same bytes");
        let right = drv(b"/nix/store/zzz-right.drv", b"same bytes");
        let different = drv(b"/nix/store/aaa-left.drv", b"different bytes");

        assert_eq!(left.content_sha256(), right.content_sha256());
        assert_eq!(
            left.content_sha256(),
            parallel_drv_output_content_sha256(b"same bytes")
        );
        assert_ne!(left.content_sha256(), different.content_sha256());
    }

    #[test]
    fn duplicate_task_fragments_are_rejected() {
        let error = collate_parallel_output_fragments([
            fragment(0, 0, StringContext::empty(), Vec::new()),
            fragment(0, 1, StringContext::empty(), Vec::new()),
        ])
        .expect_err("duplicate task fragments reject");

        assert_eq!(
            error,
            ParallelOutputDeterminismError::DuplicateTaskFragment { task_index: 0 }
        );
    }

    #[test]
    fn conflicting_drv_outputs_are_rejected() {
        let path = b"/nix/store/conflict.drv";
        let error = collate_parallel_output_fragments([
            fragment(1, 0, StringContext::empty(), vec![drv(path, b"incoming")]),
            fragment(0, 0, StringContext::empty(), vec![drv(path, b"existing")]),
        ])
        .expect_err("conflicting drv outputs reject");

        assert_eq!(
            error,
            ParallelOutputDeterminismError::ConflictingDrvOutput {
                path: path.to_vec(),
                existing_sha256: parallel_drv_output_content_sha256(b"existing"),
                incoming_sha256: parallel_drv_output_content_sha256(b"incoming"),
            }
        );
    }

    #[test]
    fn duplicate_drv_outputs_inside_one_fragment_are_collated_the_same_way() {
        let path = b"/nix/store/repeated.drv";
        let ok = collate_parallel_output_fragments([fragment(
            0,
            0,
            StringContext::empty(),
            vec![drv(path, b"same"), drv(path, b"same")],
        )])
        .expect("identical duplicate drv outputs converge");

        assert_eq!(ok.drv_output_count(), 1);
        assert_eq!(ok.drv_outputs()[0].bytes(), b"same");

        let error = collate_parallel_output_fragments([fragment(
            0,
            0,
            StringContext::empty(),
            vec![drv(path, b"left"), drv(path, b"right")],
        )])
        .expect_err("conflicting duplicate drv outputs reject");

        assert_eq!(
            error,
            ParallelOutputDeterminismError::ConflictingDrvOutput {
                path: path.to_vec(),
                existing_sha256: parallel_drv_output_content_sha256(b"left"),
                incoming_sha256: parallel_drv_output_content_sha256(b"right"),
            }
        );
    }

    #[test]
    fn empty_drv_output_paths_are_rejected() {
        let error = ParallelDrvOutput::try_new(Vec::new(), b"bytes".to_vec())
            .expect_err("empty paths reject");

        assert_eq!(error, ParallelOutputDeterminismError::EmptyDrvOutputPath);
    }

    #[test]
    fn empty_collation_has_no_outputs() {
        let collation = collate_parallel_output_fragments(Vec::<ParallelOutputFragment>::new())
            .expect("empty collation succeeds");

        assert_eq!(collation.fragment_count(), 0);
        assert!(collation.string_context().is_empty());
        assert!(collation.drv_outputs().is_empty());
    }
}
