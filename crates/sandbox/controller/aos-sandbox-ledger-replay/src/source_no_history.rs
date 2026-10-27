//! Shares the existing no-history Source replay binding as comparison DATA.
//!
//! A cold or ordinary Domain replay has no actual Source challenge borrower.
//! This private binding can mark a dependency pending but cannot close it,
//! retain a genuine challenge witness or create Source native authority.

/// Defines the same closed no-history cache binding inside a private module.
///
/// The invocation supplies its existing mechanical error and Source family
/// names lexically. The uninhabited history marker has no value constructor.
#[macro_export]
macro_rules! define_source_no_history_replay_data_v1 {
    () => {
        pub(super) use $crate::replay::challenge::SourceOriginalChallengeCheckpointV5;

        // The cold recipe always passes None. This uninhabited comparison marker
        // cannot represent a real physical challenge-history view.
        // The enclosing finite adapter passes None through the shared driver's
        // interface. Keep this marker visible there without a value constructor.
        pub(in super::super) enum SourceOriginalChallengeHistoryViewV5<'a> {
            Uninhabited(std::convert::Infallible, std::marker::PhantomData<&'a ()>),
        }

        pub(super) mod challenge {
            pub(in super::super) use $crate::replay::challenge::capture_checkpoint;
        }

        pub(super) mod replay {
            use super::super::*;

            #[derive(Clone, Default)]
            pub(in super::super) struct SourceOriginalReplayCacheV5(
                pub(in super::super) SourceOriginalReplayDataV5<()>,
            );

            impl std::ops::Deref for SourceOriginalReplayCacheV5 {
                type Target = SourceOriginalReplayDataV5<()>;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl SourceOriginalReplayCacheV5 {
                pub(in super::super) fn observe_compaction(
                    &mut self,
                    state: &source_tree_successor::State,
                ) {
                    self.0.observe_compaction(state);
                }

                #[allow(clippy::too_many_arguments)]
                pub(in super::super) fn replay_transaction(
                    &mut self,
                    state: &source_tree_successor::State,
                    transaction: &JournalTransaction,
                    challenges: Option<&super::SourceOriginalChallengeHistoryViewV5<'_>>,
                    _limits: JournalLimits,
                    _begin_sequence: u64,
                    _commit_sequence: u64,
                    _begin_offset: u64,
                    _durable_end: u64,
                    _committed_transactions: usize,
                    _identity: (u64, u64),
                ) -> Result<bool, JournalError> {
                    if challenges.is_some() {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    Ok(self.0.replay_without_history(state, transaction))
                }
            }
        }

    };
}
