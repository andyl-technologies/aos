//! Retains the entered native append interval through independent owed posts.
//!
//! The actual closed owner prepays before any post or selected stage exists.
//! A failed whole body and its post remain on the SAME immutable Arc after the
//! returned error drops. The ordinary branch adds no owner, IO or drop frontier.

use std::error::Error;

use super::*;
use super::native_backing::JournalNativeBackingV1;

pub(in crate::journal) mod captured;

pub(super) enum NativePostV1 {
    #[cfg(test)]
    Empty,
    Captured(captured::CapturedAppendPostV1),
    Controller(aos_sandbox_broker::controller_receiving::bank_launch::ControllerNativePostOriginalV1),
    Root(aos_sandbox_broker::receiving::RootWriterPostOriginalV1),
    Source(aos_sandbox_broker::source_receiving::SourceNativePostOriginalV1),
}

pub(super) struct JournalNativeIntervalOriginalV1 {
    post: NativePostV1,
    primary: Option<Result<CommitResult, JournalError>>,
    after: Option<Result<(), JournalError>>,
    stage_disposition: Option<Result<(), JournalError>>,
    post_disposition: Option<Result<(), JournalError>>,
}

impl JournalNativeIntervalOriginalV1 {
    fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(super::semantic_append::engine::OriginalAppendContextV1::receiving_construction_bytes_v1()?)?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::align_of::<Self>())?
            .checked_add(std::mem::size_of::<Arc<Self>>().checked_mul(3)?)
    }

    // Captured ordinary appends use the common stage's complete control recipe;
    // selected intervals continue to price their own existing stage contexts.
    fn captured_receiving_construction_bytes_v1() -> Option<usize> {
        use super::semantic_append::engine::OriginalAppendContextV1 as Context;

        Self::receiving_construction_bytes_v1()?
            .checked_sub(Context::receiving_construction_bytes_v1()?)?
            .checked_add(Context::ordinary_receiving_construction_bytes_v1()?)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        (match &self.post { NativePostV1::Captured(post) => post.before_failure(), _ => None })
            .or_else(|| self.primary.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| match &self.post {
                NativePostV1::Captured(post) => post.failure(),
                NativePostV1::Controller(post) => post.failure(),
                NativePostV1::Root(post) => post.failure(),
                NativePostV1::Source(post) => post.failure(),
                #[cfg(test)]
                NativePostV1::Empty => None,
            })
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.stage_disposition.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.post_disposition.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

/// Borrows the actual failed body and native post from their permanent original.
///
/// The Journal retains the same Arc. Dropping this diagnostic cannot release
/// the only native post, erase a first cause or authorize healthy reentry.
pub struct JournalNativePostFailureOriginalV1 {
    original: Arc<JournalNativeIntervalOriginalV1>,
}

impl std::fmt::Debug for JournalNativePostFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("JournalNativePostFailureOriginalV1")
            .field("failure", &self.original.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for JournalNativePostFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.original.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("selected Journal native interval is closed"),
        }
    }
}

impl Error for JournalNativePostFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> { self.original.failure() }
}

impl Journal {
    pub(super) fn begin_native_append_interval_v1(
        &mut self,
        transaction: &JournalTransaction,
        borrowed_root: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>,
    ) -> Result<(), JournalError> {
        if self.native_interval.is_some() { return Err(JournalError::Poisoned); }
        if matches!(&self.native, JournalNativeBackingV1::Ordinary(ordinary) if ordinary.captured_append.is_none()) { return Ok(()); }
        let bytes = JournalNativeIntervalOriginalV1::receiving_construction_bytes_v1()
            .ok_or(JournalError::LimitExceeded("native append interval representation"))?;
        let post = match &mut self.native {
            JournalNativeBackingV1::Ordinary(ordinary) => NativePostV1::Captured(ordinary.captured_append.as_ref()
                .ok_or(JournalError::ProtectedBoundary)?.arm()),
            JournalNativeBackingV1::Controller(writer) => {
                writer.prepay_append_interval_once(transaction, bytes).map_err(JournalError::ControllerNative)?;
                NativePostV1::Controller(writer.begin_independent_native_post_once().map_err(JournalError::ControllerNative)?)
            }
            JournalNativeBackingV1::Root(writer) => {
                NativePostV1::Root(writer.prepay_native_append_post_once_v1(
                    transaction, bytes, self.root_journal_financial.as_ref(), borrowed_root,
                ).map_err(|cause| match cause {
                    aos_sandbox_broker::receiving::RootAppendPostAdmissionErrorV1::Mechanical(cause) => JournalError::from(cause),
                    aos_sandbox_broker::receiving::RootAppendPostAdmissionErrorV1::Native(cause) => JournalError::RootNative(cause),
                    aos_sandbox_broker::receiving::RootAppendPostAdmissionErrorV1::Financial(cause) => JournalError::RootFinancial(cause),
                })?)
            }
            JournalNativeBackingV1::Source(writer) => {
                writer.prepay_append_interval_once(transaction, bytes).map_err(JournalError::SourceNative)?;
                NativePostV1::Source(writer.begin_native_post_for_append_once_v1(transaction).map_err(JournalError::SourceNative)?)
            }
        };
        self.native_interval = Some(Arc::new(JournalNativeIntervalOriginalV1 {
            post, primary: None, after: None, stage_disposition: None, post_disposition: None,
        }));
        Ok(())
    }

    pub(super) fn observe_captured_append_before_v1(&mut self) -> Result<(), JournalError> {
        let Some(original) = self.native_interval.as_mut() else { return Ok(()); };
        let body = Arc::get_mut(original).ok_or(JournalError::ProtectedBoundary)?;
        match &mut body.post {
            NativePostV1::Captured(post) => post.before_once(self.native.read_view()),
            _ => Ok(()),
        }
    }

    pub(super) fn finish_native_append_interval_v1(
        &mut self,
        primary: Result<CommitResult, JournalError>,
        mut stage: Option<native_append::JournalAppendStageV1<'_>>,
    ) -> Result<CommitResult, JournalError> {
        let Some(original) = self.native_interval.as_mut() else {
            // Ordinary retains its exact finish/error/drop boundary.
            drop(stage);
            return primary;
        };
        let body = Arc::get_mut(original).ok_or(JournalError::ProtectedBoundary)?;
        if let NativePostV1::Captured(post) = &mut body.post { post.mark_primary_return_v1(); }
        body.primary = Some(primary);
        // This is owed entered work: no ensure_healthy or fresh loan is used.
        body.after = Some(match (&self.native, &mut body.post) {
            (JournalNativeBackingV1::Ordinary(_), NativePostV1::Captured(post)) => post.after_once(self.native.read_view()),
            (JournalNativeBackingV1::Controller(writer), NativePostV1::Controller(post)) =>
                writer.finish_independent_native_post_once(post).map_err(JournalError::ControllerNative),
            (JournalNativeBackingV1::Root(writer), NativePostV1::Root(post)) =>
                writer.finish_native_post_once_v1(post).map_err(JournalError::RootNative),
            (JournalNativeBackingV1::Source(writer), NativePostV1::Source(post)) =>
                writer.finish_independent_native_post_once(post).map_err(JournalError::SourceNative),
            _ => Err(JournalError::ProtectedBoundary),
        });
        if body.failure().is_none() {
            body.stage_disposition = Some(match stage.as_mut() {
                Some(stage) => self.native.finish_append_after_posts(stage),
                None => Err(JournalError::ProtectedBoundary),
            });
        }
        // A negative stage drops into its actual owner's permanent sink before
        // the diagnostic is exposed; no positive completion is fabricated.
        drop(stage);
        if body.failure().is_none() {
            body.post_disposition = Some(match (&mut self.native, &mut body.post) {
                (JournalNativeBackingV1::Ordinary(_), NativePostV1::Captured(post)) => post.dispose(),
                (JournalNativeBackingV1::Controller(writer), NativePostV1::Controller(post)) =>
                    writer.dispose_native_post_after_upper_posts_once(post).map_err(JournalError::ControllerNative),
                (JournalNativeBackingV1::Root(_), NativePostV1::Root(post)) if post.is_complete() => Ok(()),
                (JournalNativeBackingV1::Source(writer), NativePostV1::Source(post)) =>
                    writer.dispose_native_post_after_upper_posts_once(post).map_err(JournalError::SourceNative),
                _ => Err(JournalError::ProtectedBoundary),
            });
        }
        if body.failure().is_some() {
            self.native.poison();
            return Err(JournalError::NativePostOriginal(JournalNativePostFailureOriginalV1 {
                original: Arc::clone(original),
            }));
        }
        let value = body.primary.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.native_interval = None;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_primary_io_precedes_later_post_and_survives_diagnostic_drop() {
        let native = io::Error::other("actual primary native cause");
        let body = Arc::new(JournalNativeIntervalOriginalV1 {
            post: NativePostV1::Empty,
            primary: Some(Err(JournalError::Io(native))),
            after: Some(Err(JournalError::Io(io::Error::other("later owed post")))),
            stage_disposition: None, post_disposition: None,
        });
        let pointer = body.failure().unwrap() as *const dyn Error;
        let diagnostic = JournalNativePostFailureOriginalV1 { original: Arc::clone(&body) };

        assert_eq!(diagnostic.source().unwrap() as *const dyn Error, pointer);
        assert!(diagnostic.to_string().contains("actual primary native cause"));
        drop(diagnostic);

        assert_eq!(body.failure().unwrap() as *const dyn Error, pointer);
        assert_eq!(Arc::strong_count(&body), 1);
    }

    #[test]
    fn captured_mode_preserves_whole_primary_before_independent_post_refusal() {
        let post = captured::CapturedAppendOwnerV1::new(
            "/var/lib/aos/sandbox-host", "runtime-execution.journal", 0).arm();
        let original = Arc::new(JournalNativeIntervalOriginalV1 {
            post: NativePostV1::Captured(post),
            primary: Some(Err(JournalError::Io(io::Error::other("same captured metadata error")))),
            after: Some(Err(JournalError::ProtectedBoundary)),
            stage_disposition: None, post_disposition: None,
        });
        let cause = original.failure().unwrap() as *const dyn Error;
        let diagnostic = JournalNativePostFailureOriginalV1 { original: Arc::clone(&original) };
        assert_eq!(diagnostic.source().unwrap() as *const dyn Error, cause);
        drop(diagnostic);
        assert_eq!(original.failure().unwrap() as *const dyn Error, cause);
        assert!(original.failure().unwrap().source().unwrap().downcast_ref::<io::Error>().is_some());
    }

    #[test]
    fn journal_retains_the_exact_operation_cause_after_diagnostic_disposal() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("resident-cause.journal"), JournalLimits::default(),
        ).unwrap();
        let body = Arc::new(JournalNativeIntervalOriginalV1 {
            post: NativePostV1::Empty,
            primary: Some(Err(JournalError::Io(io::Error::other("resident native cause")))),
            after: Some(Err(JournalError::ProtectedBoundary)),
            stage_disposition: None, post_disposition: None,
        });
        let pointer = body.failure().unwrap() as *const dyn Error;
        journal.native_interval = Some(Arc::clone(&body));
        let diagnostic = JournalNativePostFailureOriginalV1 { original: Arc::clone(&body) };

        assert_eq!(journal.retained_selected_failure_v1().unwrap() as *const dyn Error, pointer);
        drop(diagnostic);
        drop(body);

        let cause = journal.retained_selected_failure_v1().unwrap();
        assert_eq!(cause as *const dyn Error, pointer);
        let native = cause.source().unwrap().downcast_ref::<io::Error>().unwrap();
        assert_eq!(native.to_string(), "resident native cause");
    }
}
