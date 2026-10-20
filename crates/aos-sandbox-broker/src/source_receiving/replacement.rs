//! Keeps Source's actual replacement and independent names post together.
//!
//! The existing private Source writer supplies intrinsic custody. Its inert
//! original reference restricts representation only; it creates no recurring
//! role or cross-process signer interval. The upper Journal retains every
//! existing family, fence, Cache and final-state semantic gate.

use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension, ResourceVector};
use aos_sandbox_journal::protected_storage::FileIdentity;

use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
};
use crate::canonical_journal::coordinator::replacement::{
    CanonicalSelectedReplacementV1, selected_replacement_demand_v1,
};
use crate::canonical_journal::coordinator::selected_append::{
    SelectedAppendCustodyV1, SelectedAppendGuardV1,
};
use crate::canonical_journal::{CanonicalReplayExtentDataV1, NativeJournalDataErrorV1};
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

use super::{SourceCoordinatorWriterV1, SourceNativeErrorV1};
use super::recipe::{SOURCE_DOMAIN_DIRECTORY_V1, SOURCE_DOMAIN_JOURNAL_V1};

pub(super) struct SourceReplacementBodyV1<P> {
    before: WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
    before_result: Option<Result<(), NativeJournalDataErrorV1>>,
    native: Option<CanonicalSelectedReplacementV1<P>>,
    preparation: Option<Result<(), SourceNativeErrorV1>>,
    installation: Option<Result<(), SourceNativeErrorV1>>,
    after: WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
    after_result: Option<Result<(), NativeJournalDataErrorV1>>,
    conflict: Option<SourceNativeErrorV1>,
}

impl<P> SourceReplacementBodyV1<P> {
    fn new() -> Self {
        Self {
            before: WriterCurrentnessOriginalsV1::new(),
            before_result: None,
            native: None,
            preparation: None,
            installation: None,
            after: WriterCurrentnessOriginalsV1::new(),
            after_result: None,
            conflict: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.failure()
            .or_else(|| error(&self.before_result))
            .or_else(|| error(&self.preparation))
            .or_else(|| self.native.as_ref().and_then(CanonicalSelectedReplacementV1::failure))
            .or_else(|| error(&self.installation))
            .or_else(|| self.after.failure())
            .or_else(|| error(&self.after_result))
            .or_else(|| self.conflict.as_ref().map(|cause| cause as _))
    }
}

/// Retains a genuine Source replacement through replay and its owed names post.
///
/// No supplied File, tuple, original reference or success DATA constructs it.
/// Abandonment parks the entire reached Source and native stage in the same
/// writer's already-funded permanent sinks.
#[must_use]
pub struct SourcePreparedReplacementV1<P> {
    storage: SelectedAppendGuardV1<SourceReplacementBodyV1<P>>,
}

impl<P> SourcePreparedReplacementV1<P> {
    /// Borrows the first actual Source names, native or parser failure.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.storage.body().and_then(SourceReplacementBodyV1::failure)
    }

    fn native_mut(&mut self) -> Result<&mut CanonicalSelectedReplacementV1<P>, SourceNativeErrorV1> {
        let body = self.storage.body_mut().ok_or(SourceNativeErrorV1::Closed)?;
        if body.failure().is_some() || body.after_result.is_some() {
            return Err(SourceNativeErrorV1::Closed);
        }
        body.native.as_mut().ok_or(SourceNativeErrorV1::Closed)
    }

    /// Samples the same replacement at its original parser-identity frontier.
    ///
    /// # Errors
    /// Retains the actual native identity failure or refuses incomplete entry.
    pub fn prepare_identity_once(&mut self) -> Result<FileIdentity, SourceNativeErrorV1> {
        Ok(self.native_mut()?.prepare_identity_once()?)
    }

    /// Lends the sole canonical indexed cursor to the upper semantic engine.
    ///
    /// # Errors
    /// Preserves original native/index failure and refuses failed/ended entry.
    pub fn begin_replay_once(&mut self) -> Result<CanonicalIndexedReplayV1<'_, '_>, SourceNativeErrorV1> {
        Ok(self.native_mut()?.begin_replay_once()?)
    }

    /// Parks this actual whole failed Source/native purpose without cloning it.
    pub fn into_failure_original_v1(mut self) -> SourceReplacementFailureOriginalV1<P> {
        if let Some(body) = self.storage.body_mut() {
            if body.failure().is_none() {
                body.conflict = Some(SourceNativeErrorV1::Closed);
            }
        }
        let original = SourceReplacementFailureOriginalV1 {
            custody: Arc::clone(self.storage.custody()),
        };
        self.storage.park_unfinished();
        original
    }
}

/// Borrows the original permanently retained Source replacement failure.
pub struct SourceReplacementFailureOriginalV1<P> {
    custody: Arc<SelectedAppendCustodyV1<SourceReplacementBodyV1<P>>>,
}

impl<P> SourceReplacementFailureOriginalV1<P> {
    /// Borrows the exact retained first cause, including original native IO.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.custody.parked_body().and_then(SourceReplacementBodyV1::failure)
    }
}

impl<P> std::fmt::Debug for SourceReplacementFailureOriginalV1<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SourceReplacementFailureOriginalV1")
            .field("failure", &self.failure()).finish_non_exhaustive()
    }
}

impl<P> std::fmt::Display for SourceReplacementFailureOriginalV1<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("Source replacement was refused"),
        }
    }
}

impl<P: 'static> std::error::Error for SourceReplacementFailureOriginalV1<P> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

impl<P> SourceCoordinatorWriterV1<P> {
    /// Restricts the same actual Source original before replacement growth.
    ///
    /// Compiled upper semantic bytes describe real bounded storage only. No
    /// amount creates a writer, role interval, parser result or semantic grant.
    ///
    /// # Errors
    /// Retains checked geometry or original representation refusal and fences reuse.
    #[doc(hidden)]
    pub fn debit_replacement_semantic_bytes_v1(&mut self, bytes: usize) -> Result<(), SourceNativeErrorV1> {
        self.require_idle()?;
        if self.native_post_active || self.append_prepaid {
            return Err(SourceNativeErrorV1::Closed);
        }
        let bytes = bytes.max(self.replacement_semantic_bytes.unwrap_or(0));
        let result = (|| {
            let complete = self.replacement_representation_demand(bytes)?;
            self.original.debit_complete_representation_v1(complete)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.replacement_semantic_bytes = Some(bytes);
                Ok(())
            }
            Err(cause) => {
                self.debit_failure = Some(cause);
                self.fenced = true;
                Err(SourceNativeErrorV1::Closed)
            }
        }
    }

    fn replacement_representation_demand(&self, semantic_bytes: usize) -> Result<ResourceVector, SourceNativeErrorV1> {
        // The old state/index remains resident alongside the replacement's
        // separately bounded replay. The fixed base contains neither extent.
        let old = CanonicalReplayExtentDataV1::new(self.limits(), self.durable_end)?;
        let old_index = CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(old)
            .map_err(|cause| match cause {
                CanonicalIndexedReplayErrorV1::Native(cause) => SourceNativeErrorV1::Native(cause),
                CanonicalIndexedReplayErrorV1::Closed => SourceNativeErrorV1::Closed,
            })?;
        let replacement = selected_replacement_demand_v1::<P>(
            self.physical.native.native().state(), self.limits(), SOURCE_DOMAIN_JOURNAL_V1,
        )?;
        let bytes = std::mem::size_of::<SourcePreparedReplacementV1<P>>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceReplacementBodyV1<P>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceReplacementFailureOriginalV1<P>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(semantic_bytes))
            // The upper Journal rotates one actual authority-identity Arc
            // after successful compaction while old snapshots may retain it.
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        let names = WriterCurrentnessOriginalsV1::<NativeJournalDataErrorV1>::fixed_demand_v1(
            std::path::Path::new(SOURCE_DOMAIN_DIRECTORY_V1), SOURCE_DOMAIN_JOURNAL_V1,
        )?;
        Ok(self.base.checked_add(old.dominant_native_receiving_demand_v1()?)?
            .checked_add(old.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(old_index)?.checked_add(self.semantic_peak)?.checked_add(replacement)?
            .checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))?
            .checked_add(names)?.checked_add(names)?)
    }

    /// Starts replacement on this genuinely constructed and continuously held writer.
    ///
    /// Actual Source names run before native preparation. Even a failed before
    /// returns the whole purpose so its separately funded after can still run.
    /// Existing upper family/fence/Cache guards remain independently required.
    ///
    /// # Errors
    /// Retains representation refusal before entry or refuses a foreign active purpose.
    pub fn prepare_source_replacement_once(&mut self) -> Result<SourcePreparedReplacementV1<P>, SourceNativeErrorV1> {
        let semantic = self.replacement_semantic_bytes.ok_or(SourceNativeErrorV1::Closed)?;
        self.debit_replacement_semantic_bytes_v1(semantic)?;
        if !self.replacement_custody.enter() {
            return Err(SourceNativeErrorV1::Closed);
        }
        let mut body = SourceReplacementBodyV1::new();
        body.before_result = Some((|| {
            body.before.begin(true)?;
            let result = self.physical.observe_names_into(&mut body.before);
            body.before.finish(result)
        })());
        if matches!(body.before_result, Some(Ok(()))) {
            body.preparation = Some(match self.physical.prepare_replacement_once() {
                Ok(native) => {
                    body.native = Some(native);
                    Ok(())
                }
                Err(cause) => Err(cause.into()),
            });
        }
        if body.failure().is_some() {
            self.fenced = true;
        }
        Ok(SourcePreparedReplacementV1 {
            storage: SelectedAppendGuardV1::new(Arc::clone(&self.replacement_custody), body),
        })
    }

    /// Borrows the first purpose failure from this writer's same permanent sink.
    pub fn retained_replacement_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.debit_failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.replacement_custody.parked_body().and_then(SourceReplacementBodyV1::failure))
    }

    /// Installs the same native/index replacement after actual full upper semantics.
    ///
    /// # Errors
    /// Preserves installation failure and refuses foreign, failed or ended work.
    pub fn install_source_replacement_once(&mut self, replacement: &mut SourcePreparedReplacementV1<P>) -> Result<(), SourceNativeErrorV1> {
        if !Arc::ptr_eq(replacement.storage.custody(), &self.replacement_custody)
            || self.has_native_uncertainty_v1()
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        let body = replacement.storage.body_mut().ok_or(SourceNativeErrorV1::Closed)?;
        if body.failure().is_some() || body.after_result.is_some() || body.installation.is_some() {
            return Err(SourceNativeErrorV1::Closed);
        }
        body.installation = Some((|| {
            let native = body.native.as_mut().ok_or(SourceNativeErrorV1::Closed)?;
            self.physical.install_replacement_once(native)?;
            self.durable_end = native.installed_durable_end_v1().ok_or(SourceNativeErrorV1::Closed)?;
            Ok(())
        })());
        if matches!(body.installation, Some(Ok(()))) {
            Ok(())
        } else {
            self.fenced = true;
            Err(SourceNativeErrorV1::Closed)
        }
    }

    /// Runs the independently owed Source names post after every entered outcome.
    ///
    /// This uses the same physical owner after before/parser/install refusal or
    /// poison. A positive post cannot reopen failed work or grant disposal.
    ///
    /// # Errors
    /// Retains the actual later post cause without replacing an earlier failure.
    pub fn observe_source_replacement_after_once(&mut self, replacement: &mut SourcePreparedReplacementV1<P>) -> Result<(), SourceNativeErrorV1> {
        if !Arc::ptr_eq(replacement.storage.custody(), &self.replacement_custody) {
            return Err(SourceNativeErrorV1::Closed);
        }
        let body = replacement.storage.body_mut().ok_or(SourceNativeErrorV1::Closed)?;
        if body.after_result.is_some() {
            return Err(SourceNativeErrorV1::Closed);
        }
        body.after_result = Some((|| {
            body.after.begin(true)?;
            let result = self.physical.observe_names_into(&mut body.after);
            body.after.finish(result)
        })());
        if body.failure().is_some() || !matches!(body.after_result, Some(Ok(()))) {
            self.fenced = true;
            Err(SourceNativeErrorV1::Closed)
        } else {
            Ok(())
        }
    }

    /// Retires physical work only after its actual Source post and upper posts.
    ///
    /// # Errors
    /// Refuses foreign, failed, uninstalled or unobserved work without refunding debt.
    pub fn finish_source_replacement_after_posts_once(&mut self, replacement: &mut SourcePreparedReplacementV1<P>) -> Result<(), SourceNativeErrorV1> {
        if !Arc::ptr_eq(replacement.storage.custody(), &self.replacement_custody)
            || self.has_native_uncertainty_v1()
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        let body = replacement.storage.body_mut().ok_or(SourceNativeErrorV1::Closed)?;
        if body.failure().is_some() || !matches!(body.after_result, Some(Ok(())))
            || !matches!(body.installation, Some(Ok(())))
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        self.physical.finish_replacement_after_posts_once(
            body.native.as_mut().ok_or(SourceNativeErrorV1::Closed)?,
        )?;
        let completed = replacement.storage.take_body().ok_or(SourceNativeErrorV1::Closed)?;
        drop(completed);
        self.replacement_custody.release_active();
        Ok(())
    }
}

fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_later_names_post_cannot_replace_the_parked_first_io_cause() {
        let first = std::io::Error::other(std::io::Error::from_raw_os_error(9));
        let pointer = first.get_ref().unwrap() as *const _;
        let mut body = SourceReplacementBodyV1::<()>::new();
        body.before_result = Some(Err(NativeJournalDataErrorV1::Io(first)));
        body.after_result = Some(Err(NativeJournalDataErrorV1::Io(
            std::io::Error::from_raw_os_error(13),
        )));
        let custody = Arc::new(SelectedAppendCustodyV1::new());
        assert!(custody.enter());
        let prepared = SourcePreparedReplacementV1 {
            storage: SelectedAppendGuardV1::new(Arc::clone(&custody), body),
        };

        let returned = prepared.into_failure_original_v1();
        drop(returned);

        let cause = custody.parked_body().unwrap().failure().unwrap();
        let NativeJournalDataErrorV1::Io(actual) = cause.downcast_ref::<NativeJournalDataErrorV1>().unwrap() else {
            panic!("the original IO classification changed");
        };
        assert!(std::ptr::eq(pointer, actual.get_ref().unwrap() as *const _));
        assert_eq!(actual.get_ref().unwrap().downcast_ref::<std::io::Error>()
            .unwrap().raw_os_error(), Some(9));
        assert!(!custody.enter());
    }
}
