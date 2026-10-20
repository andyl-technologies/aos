//! Drives selected replacement through the sole upper semantic replay engine.
//!
//! The real role prepays its native and compiled upper representations. The
//! Journal keeps both physical replacement and upper semantic prefix until all
//! original family checks and independent native posts settle. A returned
//! failure shares this same permanent body; it cannot dispose ambiguous custody.

use std::error::Error;

use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1;
use aos_sandbox_broker::controller_receiving::bank_launch::{ControllerPreparedReplacementV1, ControllerNativePostOriginalV1};
use aos_sandbox_broker::receiving::{RootPreparedReplacementV1, RootWriterErrorV1, RootWriterPostOriginalV1};
use aos_sandbox_broker::source_receiving::SourcePreparedReplacementV1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_ledger_replay::cold::{ColdReplayOriginalV1, ColdReplayRemainderDataV1};

use super::native_backing::{JournalNativeBackingV1, Selection};
use super::semantic_remainder::ColdSemanticRemainderOriginalV1;
use super::*;

type CommonSemantic = ColdReplayOriginalV1<CanonicalIndexedReplayErrorV1>;
type RootSemantic = ColdReplayOriginalV1<RootWriterErrorV1>;

enum Stage {
    Controller(ControllerPreparedReplacementV1<Selection>),
    Root(RootPreparedReplacementV1<Selection>),
    Source(SourcePreparedReplacementV1<Selection>),
}

enum Semantics { Common(CommonSemantic), Root(RootSemantic) }
enum Post { Controller(ControllerNativePostOriginalV1), Root(RootWriterPostOriginalV1) }

pub(super) struct JournalReplacementOriginalV1 {
    stage: Option<Stage>,
    semantic: Option<Semantics>,
    conversion: ColdSemanticRemainderOriginalV1,
    post: Option<Post>,
    primary: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    disposition: Option<Result<(), JournalError>>,
    post_disposition: Option<Result<(), JournalError>>,
    semantic_refused: bool,
    outer_refused: bool,
}

impl JournalReplacementOriginalV1 {
    fn construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::align_of::<Self>())?
            .checked_add(std::mem::size_of::<Arc<Self>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<JournalAuthorityInstance>())?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::align_of::<JournalAuthorityInstance>())
    }

    fn stage_failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.stage.as_ref()? {
            Stage::Controller(stage) => stage.failure(),
            Stage::Root(stage) => stage.failure(),
            Stage::Source(stage) => stage.failure(),
        }
    }

    fn semantic_failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.semantic.as_ref()? {
            Semantics::Common(semantic) => semantic.failure(),
            Semantics::Root(semantic) => semantic.failure(),
        }.or_else(|| self.conversion.failure())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // These actual outer final checks follow installation and precede the
        // independent Source after. Preserve their earlier owned Result even
        // when that later after reports failure inside the Source stage.
        if self.outer_refused {
            if let Some(Err(cause)) = &self.primary { return Some(cause); }
        }
        // Source's independent after may fail after the earlier upper semantic
        // refusal; that later stage error must not replace the original cause.
        if self.semantic_refused {
            if let Some(cause) = self.semantic_failure() { return Some(cause); }
        }
        self.stage_failure().or_else(|| self.semantic_failure())
            .or_else(|| self.primary.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| match self.post.as_ref()? {
                Post::Controller(post) => post.failure(),
                Post::Root(post) => post.failure(),
            })
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.disposition.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.post_disposition.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    fn take_remainder(&mut self) -> Option<ColdReplayRemainderDataV1> {
        match self.semantic.as_mut()? {
            Semantics::Common(semantic) => semantic.take_remainder_once(),
            Semantics::Root(semantic) => semantic.take_remainder_once(),
        }
    }
}

/// Keeps the actual upper semantic/native replacement failure original alive.
pub struct JournalReplacementFailureOriginalV1 { original: Arc<JournalReplacementOriginalV1> }

impl std::fmt::Debug for JournalReplacementFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("JournalReplacementFailureOriginalV1")
            .field("failure", &self.original.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for JournalReplacementFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.original.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("selected Journal replacement is closed"),
        }
    }
}

impl Error for JournalReplacementFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> { self.original.failure() }
}

impl Journal {
    pub(super) fn compact_selected_v1(&mut self) -> Result<(), JournalError> {
        if self.replacement_original.is_some() { return Err(JournalError::Poisoned); }
        let mut body = JournalReplacementOriginalV1 {
            stage: None, semantic: None, post: None, primary: None, after: None,
            conversion: ColdSemanticRemainderOriginalV1::new(),
            disposition: None, post_disposition: None, semantic_refused: false, outer_refused: false,
        };
        let extent = aos_sandbox_broker::canonical_journal::coordinator::replacement::
            replacement_replay_extent_data_v1(self.native.state(), self.native.limits())
            .map_err(project_ordinary_replacement_error)?;
        let upper = protected_journal_preopen_replay_extent_for_prefix_v1(extent.limits(), extent.native_bytes())?
            .dominant_semantic_receiving_demand_v1()?;
        let common = CommonSemantic::fixed_demand_v1()?;
        let root = RootSemantic::fixed_demand_v1()?;
        let own = JournalReplacementOriginalV1::construction_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("selected replacement representation"))?;
        let conversion = ColdSemanticRemainderOriginalV1::receiving_demand_v1()?;
        let complete_upper = upper.checked_add(common.componentwise_max(root))
            .and_then(|demand| demand.checked_add(conversion))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, own)))
            .map_err(|_| JournalError::LimitExceeded("selected replacement representation"))?;
        let bytes = usize::try_from(complete_upper.get(D::MemoryBytes))
            .map_err(|_| JournalError::LimitExceeded("selected replacement representation"))?;
        // Each branch reaches only its genuine native owner. Cost DATA selects
        // neither the role nor semantic success and cannot construct a stage.
        match &mut self.native {
            JournalNativeBackingV1::Controller(writer) => {
                writer.debit_replacement_semantic_bytes_v1(bytes).map_err(JournalError::ControllerNative)?;
                body.post = Some(Post::Controller(writer.begin_independent_native_post_once().map_err(JournalError::ControllerNative)?));
            }
            JournalNativeBackingV1::Root(writer) => {
                let demand = writer.replacement_demand_v1().map_err(JournalError::RootNative)?
                    .checked_add(writer.native_post_demand_v1().map_err(JournalError::RootNative)?)
                    .and_then(|demand| demand.checked_add(complete_upper))
                    .map_err(|_| JournalError::LimitExceeded("Root replacement representation"))?;
                let financial = self.root_journal_financial.as_ref().ok_or(JournalError::ProtectedBoundary)?;
                financial.debit_v1(writer, demand).map_err(|_| JournalError::RootFinancial(financial.clone()))?;
                body.post = Some(Post::Root(writer.arm_native_post_once_v1().map_err(JournalError::RootNative)?));
            }
            JournalNativeBackingV1::Source(writer) => {
                writer.debit_replacement_semantic_bytes_v1(bytes).map_err(JournalError::SourceNative)?;
            }
            JournalNativeBackingV1::Ordinary(_) => return Err(JournalError::ProtectedBoundary),
        }
        self.replacement_original = Some(Arc::new(body));
        let body = Arc::get_mut(self.replacement_original.as_mut().ok_or(JournalError::ProtectedBoundary)?)
            .ok_or(JournalError::ProtectedBoundary)?;
        let primary = (|| {
            match &mut self.native {
                JournalNativeBackingV1::Controller(writer) => {
                    body.stage = Some(Stage::Controller(writer.prepare_controller_replacement_once().map_err(JournalError::ControllerNative)?));
                    body.semantic = Some(Semantics::Common(CommonSemantic::new()));
                }
                JournalNativeBackingV1::Root(writer) => {
                    body.stage = Some(Stage::Root(writer.prepare_replacement_once().map_err(JournalError::RootNative)?));
                    body.semantic = Some(Semantics::Root(RootSemantic::new()));
                }
                JournalNativeBackingV1::Source(writer) => {
                    body.stage = Some(Stage::Source(writer.prepare_source_replacement_once().map_err(JournalError::SourceNative)?));
                    body.semantic = Some(Semantics::Common(CommonSemantic::new()));
                }
                _ => return Err(JournalError::ProtectedBoundary),
            }
            let limits = self.native.limits();
            let semantic_result = match (body.stage.as_mut(), body.semantic.as_mut()) {
                (Some(Stage::Controller(stage)), Some(Semantics::Common(semantic))) => {
                    let identity = stage.prepare_identity_once().map_err(JournalError::ControllerNative)?;
                    let mut cursor = stage.begin_replay_once().map_err(JournalError::ControllerNative)?;
                    semantic.observe_indexed_once(&mut cursor, identity, limits)
                }
                (Some(Stage::Root(stage)), Some(Semantics::Root(semantic))) => {
                    let identity = stage.prepare_identity_once().map_err(JournalError::RootNative)?;
                    let mut cursor = stage.begin_replay_once().map_err(JournalError::RootNative)?;
                    semantic.observe_root_once(&mut cursor, identity, limits)
                }
                (Some(Stage::Source(stage)), Some(Semantics::Common(semantic))) => {
                    let identity = stage.prepare_identity_once().map_err(JournalError::SourceNative)?;
                    let mut cursor = stage.begin_replay_once().map_err(JournalError::SourceNative)?;
                    semantic.observe_indexed_once(&mut cursor, identity, limits)
                }
                _ => return Err(JournalError::ProtectedBoundary),
            };
            if semantic_result.is_err() {
                body.semantic_refused = true;
                return Err(JournalError::ProtectedBoundary);
            }
            let mut remainder = body.take_remainder();
            body.conversion.observe_once(&mut remainder);
            if !body.conversion.ready() {
                body.semantic_refused = true;
                return Err(JournalError::ProtectedBoundary);
            }
            match (&mut self.native, body.stage.as_mut()) {
                (JournalNativeBackingV1::Controller(writer), Some(Stage::Controller(stage))) =>
                    writer.install_controller_replacement_once(stage).map_err(JournalError::ControllerNative)?,
                (JournalNativeBackingV1::Root(writer), Some(Stage::Root(stage))) =>
                    writer.install_replacement_once(stage).map_err(JournalError::RootNative)?,
                (JournalNativeBackingV1::Source(writer), Some(Stage::Source(stage))) =>
                    writer.install_source_replacement_once(stage).map_err(JournalError::SourceNative)?,
                _ => return Err(JournalError::ProtectedBoundary),
            }
            let remainder = body.conversion.take_once().ok_or(JournalError::ProtectedBoundary)?;
            self.source_challenge_history = remainder.source_challenge_history;
            self.source_original_replay = remainder.source_original_replay;
            self.source_history_compacted = remainder.source_history_compacted;
            self.q04_lower_history_present = remainder.q04_lower_history_present;
            self.authority_instance = Arc::new(JournalAuthorityInstance);
            Ok(())
        })();
        let positive = primary.is_ok();
        body.primary = Some(primary);
        if positive { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(super) fn finish_selected_compaction_v1(&mut self, outer: Result<(), JournalError>) -> Result<(), JournalError> {
        let Some(original) = self.replacement_original.as_mut() else { return outer; };
        let body = Arc::get_mut(original).ok_or(JournalError::ProtectedBoundary)?;
        // Preserve earlier semantic/native first cause; store a later outer
        // family refusal only when the physical/semantic body was successful.
        if outer.is_err() && matches!(body.primary, Some(Ok(()))) {
            body.outer_refused = true;
            body.primary = Some(outer);
        }
        body.after = Some(match (&mut self.native, body.stage.as_mut(), body.post.as_mut()) {
            (JournalNativeBackingV1::Controller(writer), _, Some(Post::Controller(post))) =>
                writer.finish_independent_native_post_once(post).map_err(JournalError::ControllerNative),
            (JournalNativeBackingV1::Root(writer), _, Some(Post::Root(post))) =>
                writer.finish_native_post_once_v1(post).map_err(JournalError::RootNative),
            (JournalNativeBackingV1::Source(writer), Some(Stage::Source(stage)), _) =>
                writer.observe_source_replacement_after_once(stage).map_err(JournalError::SourceNative),
            _ => Err(JournalError::ProtectedBoundary),
        });
        if body.failure().is_none() {
            body.disposition = Some(match (&mut self.native, body.stage.as_mut()) {
                (JournalNativeBackingV1::Controller(writer), Some(Stage::Controller(stage))) =>
                    writer.finish_controller_replacement_after_posts_once(stage).map_err(JournalError::ControllerNative),
                (JournalNativeBackingV1::Root(writer), Some(Stage::Root(stage))) =>
                    writer.finish_replacement_after_posts_once(stage).map_err(JournalError::RootNative),
                (JournalNativeBackingV1::Source(writer), Some(Stage::Source(stage))) =>
                    writer.finish_source_replacement_after_posts_once(stage).map_err(JournalError::SourceNative),
                _ => Err(JournalError::ProtectedBoundary),
            });
        }
        if body.failure().is_none() {
            body.post_disposition = Some(match (&self.native, body.post.as_mut()) {
                (JournalNativeBackingV1::Controller(writer), Some(Post::Controller(post))) =>
                    writer.dispose_native_post_after_upper_posts_once(post).map_err(JournalError::ControllerNative),
                (JournalNativeBackingV1::Root(_), Some(Post::Root(post))) if post.is_complete() => Ok(()),
                (JournalNativeBackingV1::Source(_), None) => Ok(()),
                _ => Err(JournalError::ProtectedBoundary),
            });
        }
        if body.failure().is_some() {
            self.native.poison();
            return Err(JournalError::ReplacementOriginal(JournalReplacementFailureOriginalV1 { original: Arc::clone(original) }));
        }
        self.replacement_original = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earlier_whole_primary_cause_survives_later_after_failure_and_error_drop() {
        let body = Arc::new(JournalReplacementOriginalV1 {
            stage: None, semantic: None, post: None,
            conversion: ColdSemanticRemainderOriginalV1::new(),
            primary: Some(Err(JournalError::Io(io::Error::other("replacement primary")))),
            after: Some(Err(JournalError::Io(io::Error::other("later after")))),
            disposition: None, post_disposition: None, semantic_refused: false, outer_refused: false,
        });
        let pointer = body.failure().unwrap() as *const dyn Error;
        let diagnostic = JournalReplacementFailureOriginalV1 { original: Arc::clone(&body) };

        assert_eq!(diagnostic.source().unwrap() as *const dyn Error, pointer);
        drop(diagnostic);

        assert_eq!(body.failure().unwrap() as *const dyn Error, pointer);
        let native = body.failure().unwrap().source().unwrap();
        assert!(native.is::<io::Error>());
        assert_eq!(native.to_string(), "replacement primary");
    }
}
