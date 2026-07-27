//! Value-generic prototype for transition-specialized demand regions.
//!
//! This module isolates the first executable shape of a whole-demand region
//! machine from [`TreeWalk`](super::TreeWalk). A [`RegionProgram`] contains
//! only immutable code identity and control flow. Runtime values are supplied
//! separately to [`execute_body684`], through the [`RegionValueModel`] trait,
//! so compiling or caching a program cannot accidentally specialize it to
//! heap addresses, string contents, list lengths, or branch outcomes.
//!
//! The initial tape implements the behavior of the `lib/modules.nix`
//! `body684` name-deduplication loop:
//!
//! ```text
//! dedup acc remaining =
//!   if remaining == [] then acc
//!   else
//!     let candidate = head remaining;
//!     in dedup
//!          (if candidate is already in acc then acc else acc ++ [candidate])
//!          (tail remaining)
//! ```
//!
//! Branches and the backedge are explicit tape operations. The executor does
//! not call the tree walker, force a thunk, allocate a lexical frame, or
//! recursively invoke itself. Unsupported value shapes decline without
//! publishing an output value.

/// Encoding version for prototype region programs and cache keys.
const REGION_FORMAT_VERSION: u32 = 1;

/// Immutable identity of one compiled region.
///
/// Every field describes source code or its resolver layout. Runtime values
/// deliberately have no representation in this key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct TraceKey {
    /// Region tape encoding version.
    format_version: u32,
    /// Exact digest of the lowered IR and resolver metadata.
    module_digest: [u8; 32],
    /// Entry IR node in the owning module.
    entry: u32,
    /// Resolver frame associated with the entry closure.
    resolver_frame: u32,
    /// Exact digest of the versioned closure-capture layout.
    capture_layout_digest: [u8; 32],
}

impl TraceKey {
    /// Constructs an exact source-and-layout key for a body-684 program.
    pub(super) const fn new(
        module_digest: [u8; 32],
        entry: u32,
        resolver_frame: u32,
        capture_layout_digest: [u8; 32],
    ) -> Self {
        Self {
            format_version: REGION_FORMAT_VERSION,
            module_digest,
            entry,
            resolver_frame,
            capture_layout_digest,
        }
    }
}

/// Zero-based address of an operation in a region tape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegionPc(u32);

impl RegionPc {
    /// Converts the compact address to a slice index.
    fn index(self) -> Option<usize> {
        usize::try_from(self.0).ok()
    }
}

/// One explicit control or data transition in the body-684 tape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegionOp {
    /// Chooses the lazy empty-list result or the nonempty loop setup.
    BranchRemainingEmpty {
        /// Target that returns the untouched accumulator.
        empty: RegionPc,
        /// Target that starts the nonempty loop.
        nonempty: RegionPc,
    },
    /// Copies and validates the accumulator into unpublished builder storage.
    InitOutput {
        /// Next operation after successful validation.
        next: RegionPc,
    },
    /// Chooses loop completion or the next element.
    BranchRemainingDone {
        /// Target that publishes the completed result.
        done: RegionPc,
        /// Target that loads the current candidate.
        item: RegionPc,
    },
    /// Loads and validates the current remaining-list element.
    LoadCandidate {
        /// Next operation after a string candidate was loaded.
        next: RegionPc,
    },
    /// Tests whether the current candidate already occurs in the builder.
    BranchCandidateSeen {
        /// Target used when an equal string already occurs.
        seen: RegionPc,
        /// Target used for a new string.
        unseen: RegionPc,
    },
    /// Adds the current candidate to unpublished builder storage.
    PushCandidate {
        /// Next operation after the append.
        next: RegionPc,
    },
    /// Advances the loop index and follows the explicit backedge.
    AdvanceRemaining {
        /// Loop-header target.
        next: RegionPc,
    },
    /// Returns the original accumulator or publishes one final list.
    PublishResult,
    /// Returns the accumulator without inspecting it.
    ReturnAccumulator,
}

/// Immutable, reusable code for one value-generic region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RegionProgram {
    /// Exact source and resolver identity.
    key: TraceKey,
    /// First operation executed by the machine.
    entry: RegionPc,
    /// Explicit branch-and-loop tape.
    ops: Box<[RegionOp]>,
}

impl RegionProgram {
    /// Builds the canonical value-generic body-684 tape.
    pub(super) fn body684(key: TraceKey) -> Self {
        Self {
            key,
            entry: RegionPc(0),
            ops: Box::new([
                RegionOp::BranchRemainingEmpty {
                    empty: RegionPc(8),
                    nonempty: RegionPc(1),
                },
                RegionOp::InitOutput { next: RegionPc(2) },
                RegionOp::BranchRemainingDone {
                    done: RegionPc(7),
                    item: RegionPc(3),
                },
                RegionOp::LoadCandidate { next: RegionPc(4) },
                RegionOp::BranchCandidateSeen {
                    seen: RegionPc(6),
                    unseen: RegionPc(5),
                },
                RegionOp::PushCandidate { next: RegionPc(6) },
                RegionOp::AdvanceRemaining { next: RegionPc(2) },
                RegionOp::PublishResult,
                RegionOp::ReturnAccumulator,
            ]),
        }
    }

    /// Returns the program's immutable cache identity.
    pub(super) const fn key(&self) -> TraceKey {
        self.key
    }

    /// Decodes one operation, declining malformed control flow.
    fn op(&self, pc: RegionPc) -> Result<RegionOp, RegionDecline> {
        let index = pc.index().ok_or(RegionDecline::MalformedProgram)?;
        self.ops
            .get(index)
            .copied()
            .ok_or(RegionDecline::MalformedProgram)
    }
}

/// Value operations required by the initial region tape.
///
/// Implementations expose immutable list and string observations and a single
/// publication door. The executor owns all intermediate vectors, so a decline
/// cannot partially mutate a caller-visible value.
pub(super) trait RegionValueModel {
    /// Runtime value carried through machine slots.
    type Value: Clone;

    /// Clones a list's elements, or returns `None` for a non-list value.
    fn list_elements(&self, value: &Self::Value) -> Option<Vec<Self::Value>>;

    /// Reports whether a value is an already evaluated string.
    fn is_string(&self, value: &Self::Value) -> bool;

    /// Compares two already evaluated strings.
    ///
    /// Returns `None` if either operand is not a supported string.
    fn strings_equal(&self, left: &Self::Value, right: &Self::Value) -> Option<bool>;

    /// Publishes the only result allocation permitted by the prototype.
    fn publish_list(&self, elements: Vec<Self::Value>) -> Option<Self::Value>;
}

/// Fail-closed reasons returned before a region result is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RegionDecline {
    /// A branch or backedge addressed an operation outside the tape.
    MalformedProgram,
    /// The remaining argument was not an already evaluated list.
    UnsupportedRemaining,
    /// A remaining-list element was not an already evaluated string.
    UnsupportedRemainingElement,
    /// The nonempty path's accumulator was not an already evaluated list.
    UnsupportedAccumulator,
    /// An accumulator element was not an already evaluated string.
    UnsupportedAccumulatorElement,
    /// The value model could not publish the final list.
    ResultPublicationFailed,
}

/// Mutable state for one callback-free body-684 execution.
struct RegionState<V> {
    /// Original accumulator, retained for the empty and unchanged cases.
    accumulator: V,
    /// Validated remaining-list spine.
    remaining: Vec<V>,
    /// Current remaining-list index.
    remaining_index: usize,
    /// Current string candidate between load and advance.
    candidate: Option<V>,
    /// Unpublished output elements, initialized only on the nonempty path.
    output: Option<Vec<V>>,
    /// Whether at least one candidate was appended.
    changed: bool,
}

/// Executes a body-684 tape without tree-walk callbacks or recursive dispatch.
///
/// The empty path observes only `remaining` and returns `accumulator`
/// untouched. The nonempty path validates every accumulator element before it
/// enters the loop. Unsupported values and malformed programs decline before
/// [`RegionValueModel::publish_list`] is called.
///
/// # Errors
///
/// Returns [`RegionDecline`] when the tape is malformed, either input contains
/// a value outside the list-of-strings prototype domain, or final list
/// publication fails.
pub(super) fn execute_body684<M: RegionValueModel>(
    program: &RegionProgram,
    model: &M,
    accumulator: M::Value,
    remaining: M::Value,
) -> Result<M::Value, RegionDecline> {
    let remaining = model
        .list_elements(&remaining)
        .ok_or(RegionDecline::UnsupportedRemaining)?;
    let mut state = RegionState {
        accumulator,
        remaining,
        remaining_index: 0,
        candidate: None,
        output: None,
        changed: false,
    };
    let mut pc = program.entry;
    loop {
        match program.op(pc)? {
            RegionOp::BranchRemainingEmpty { empty, nonempty } => {
                pc = if state.remaining.is_empty() {
                    empty
                } else {
                    nonempty
                };
            }
            RegionOp::InitOutput { next } => {
                let output = model
                    .list_elements(&state.accumulator)
                    .ok_or(RegionDecline::UnsupportedAccumulator)?;
                if output.iter().any(|value| !model.is_string(value)) {
                    return Err(RegionDecline::UnsupportedAccumulatorElement);
                }
                state.output = Some(output);
                pc = next;
            }
            RegionOp::BranchRemainingDone { done, item } => {
                pc = if state.remaining_index == state.remaining.len() {
                    done
                } else if state.remaining_index < state.remaining.len() {
                    item
                } else {
                    return Err(RegionDecline::MalformedProgram);
                };
            }
            RegionOp::LoadCandidate { next } => {
                let candidate = state
                    .remaining
                    .get(state.remaining_index)
                    .cloned()
                    .ok_or(RegionDecline::MalformedProgram)?;
                if !model.is_string(&candidate) {
                    return Err(RegionDecline::UnsupportedRemainingElement);
                }
                state.candidate = Some(candidate);
                pc = next;
            }
            RegionOp::BranchCandidateSeen { seen, unseen } => {
                let candidate = state
                    .candidate
                    .as_ref()
                    .ok_or(RegionDecline::MalformedProgram)?;
                let output = state
                    .output
                    .as_ref()
                    .ok_or(RegionDecline::MalformedProgram)?;
                let mut duplicate = false;
                for existing in output {
                    let equal = model
                        .strings_equal(existing, candidate)
                        .ok_or(RegionDecline::UnsupportedAccumulatorElement)?;
                    if equal {
                        duplicate = true;
                        break;
                    }
                }
                pc = if duplicate { seen } else { unseen };
            }
            RegionOp::PushCandidate { next } => {
                let candidate = state
                    .candidate
                    .as_ref()
                    .cloned()
                    .ok_or(RegionDecline::MalformedProgram)?;
                state
                    .output
                    .as_mut()
                    .ok_or(RegionDecline::MalformedProgram)?
                    .push(candidate);
                state.changed = true;
                pc = next;
            }
            RegionOp::AdvanceRemaining { next } => {
                state.remaining_index = state
                    .remaining_index
                    .checked_add(1)
                    .ok_or(RegionDecline::MalformedProgram)?;
                state.candidate = None;
                pc = next;
            }
            RegionOp::PublishResult => {
                if !state.changed {
                    return Ok(state.accumulator);
                }
                let output = state.output.ok_or(RegionDecline::MalformedProgram)?;
                return model
                    .publish_list(output)
                    .ok_or(RegionDecline::ResultPublicationFailed);
            }
            RegionOp::ReturnAccumulator => return Ok(state.accumulator),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Small immutable value domain used to validate generic machine behavior.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum TestValue {
        String(&'static str),
        List(Vec<TestValue>),
        Integer(i64),
        Bomb,
    }

    /// Test model that counts list observations and result publications.
    #[derive(Default)]
    struct TestModel {
        list_observations: Cell<u64>,
        publications: Cell<u64>,
    }

    impl RegionValueModel for TestModel {
        type Value = TestValue;

        fn list_elements(&self, value: &Self::Value) -> Option<Vec<Self::Value>> {
            self.list_observations
                .set(self.list_observations.get().saturating_add(1));
            match value {
                TestValue::List(elements) => Some(elements.clone()),
                TestValue::String(_) | TestValue::Integer(_) | TestValue::Bomb => None,
            }
        }

        fn is_string(&self, value: &Self::Value) -> bool {
            matches!(value, TestValue::String(_))
        }

        fn strings_equal(&self, left: &Self::Value, right: &Self::Value) -> Option<bool> {
            match (left, right) {
                (TestValue::String(left), TestValue::String(right)) => Some(left == right),
                _ => None,
            }
        }

        fn publish_list(&self, elements: Vec<Self::Value>) -> Option<Self::Value> {
            self.publications
                .set(self.publications.get().saturating_add(1));
            Some(TestValue::List(elements))
        }
    }

    /// Returns one exact source key shared by all value-generic test runs.
    fn test_key() -> TraceKey {
        TraceKey::new([7; 32], 684, 54, [11; 32])
    }

    /// Creates a list of string values in source order.
    fn strings(values: &[&'static str]) -> TestValue {
        TestValue::List(values.iter().copied().map(TestValue::String).collect())
    }

    #[test]
    fn one_program_handles_distinct_runtime_values() {
        let program = RegionProgram::body684(test_key());
        let first_model = TestModel::default();
        let first = execute_body684(
            &program,
            &first_model,
            strings(&["base"]),
            strings(&["b", "a", "b"]),
        )
        .expect("first generic execution");
        assert_eq!(first, strings(&["base", "b", "a"]));

        let second_model = TestModel::default();
        let second = execute_body684(
            &program,
            &second_model,
            strings(&[]),
            strings(&["x", "x", "y"]),
        )
        .expect("second generic execution");
        assert_eq!(second, strings(&["x", "y"]));
        assert_eq!(program.key(), test_key());
    }

    #[test]
    fn preserves_accumulator_and_first_occurrence_order() {
        let program = RegionProgram::body684(test_key());
        let model = TestModel::default();
        let result = execute_body684(
            &program,
            &model,
            strings(&["z", "a"]),
            strings(&["a", "b", "z", "c", "b"]),
        )
        .expect("ordered dedup execution");
        assert_eq!(result, strings(&["z", "a", "b", "c"]));
        assert_eq!(model.publications.get(), 1);
    }

    #[test]
    fn empty_remaining_does_not_observe_accumulator() {
        let program = RegionProgram::body684(test_key());
        let model = TestModel::default();
        let result = execute_body684(&program, &model, TestValue::Bomb, strings(&[]))
            .expect("empty remaining returns lazy accumulator");
        assert_eq!(result, TestValue::Bomb);
        assert_eq!(model.list_observations.get(), 1);
        assert_eq!(model.publications.get(), 0);
    }

    #[test]
    fn unchanged_nonempty_result_reuses_accumulator() {
        let program = RegionProgram::body684(test_key());
        let model = TestModel::default();
        let accumulator = strings(&["a", "b"]);
        let result = execute_body684(
            &program,
            &model,
            accumulator.clone(),
            strings(&["b", "a", "b"]),
        )
        .expect("duplicate-only execution");
        assert_eq!(result, accumulator);
        assert_eq!(model.publications.get(), 0);
    }

    #[test]
    fn unsupported_runtime_types_decline_without_publication() {
        let program = RegionProgram::body684(test_key());

        let non_list_model = TestModel::default();
        let non_list = execute_body684(
            &program,
            &non_list_model,
            strings(&[]),
            TestValue::Integer(1),
        );
        assert_eq!(non_list, Err(RegionDecline::UnsupportedRemaining));
        assert_eq!(non_list_model.publications.get(), 0);

        let bad_acc_model = TestModel::default();
        let bad_acc = execute_body684(
            &program,
            &bad_acc_model,
            TestValue::Integer(1),
            strings(&["x"]),
        );
        assert_eq!(bad_acc, Err(RegionDecline::UnsupportedAccumulator));
        assert_eq!(bad_acc_model.publications.get(), 0);

        let bad_acc_element_model = TestModel::default();
        let bad_acc_element = execute_body684(
            &program,
            &bad_acc_element_model,
            TestValue::List(vec![TestValue::Integer(1)]),
            strings(&["x"]),
        );
        assert_eq!(
            bad_acc_element,
            Err(RegionDecline::UnsupportedAccumulatorElement)
        );
        assert_eq!(bad_acc_element_model.publications.get(), 0);

        let bad_element_model = TestModel::default();
        let bad_element = execute_body684(
            &program,
            &bad_element_model,
            strings(&[]),
            TestValue::List(vec![TestValue::Integer(1)]),
        );
        assert_eq!(bad_element, Err(RegionDecline::UnsupportedRemainingElement));
        assert_eq!(bad_element_model.publications.get(), 0);
    }

    #[test]
    fn trace_identity_changes_only_with_static_code_metadata() {
        let base = RegionProgram::body684(test_key());
        let changed_module = RegionProgram::body684(TraceKey::new([8; 32], 684, 54, [11; 32]));
        let changed_layout = RegionProgram::body684(TraceKey::new([7; 32], 684, 54, [12; 32]));
        assert_ne!(base.key(), changed_module.key());
        assert_ne!(base.key(), changed_layout.key());
    }
}
