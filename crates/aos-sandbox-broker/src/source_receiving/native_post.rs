//! Prearms the existing held Source writer's independent native names post.
//!
//! The upper Journal owns semantic entry and every other post. This native
//! destination remains usable after that body fails or poisons the writer;
//! its completion never supplies Source semantics or a recurring signer F.

use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension, ResourceVector};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::canonical_journal::NativeJournalDataErrorV1;
use crate::canonical_journal::coordinator::selected_append::SelectedAppendCustodyV1;
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

use super::append::SourceAppendBodyV1;
use super::recipe::{SOURCE_DOMAIN_DIRECTORY_V1, SOURCE_DOMAIN_JOURNAL_V1};
use super::{SourceCoordinatorWriterV1, SourceNativeErrorV1};

/// Retains the same Source writer's actual prearmed native post.
///
/// Its constructor is private to the genuinely held coordinator. A failed or
/// abandoned post terminates before releasing any reached original.
#[must_use]
pub struct SourceNativePostOriginalV1 {
    identity: Arc<SelectedAppendCustodyV1<SourceAppendBodyV1>>,
    sample: WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
    returned: Option<Result<(), NativeJournalDataErrorV1>>,
    settled: bool,
}

impl SourceNativePostOriginalV1 {
    /// Bounds this actual carrier and its single fixed Source names sample.
    ///
    /// # Errors
    /// Rejects checked receiving byte or descriptor arithmetic overflow.
    pub fn receiving_demand_v1() -> Result<ResourceVector, SourceNativeErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes)
            .checked_add(WriterCurrentnessOriginalsV1::<NativeJournalDataErrorV1>::fixed_demand_v1(
                Path::new(SOURCE_DOMAIN_DIRECTORY_V1), SOURCE_DOMAIN_JOURNAL_V1,
            )?)?)
    }

    /// Borrows the actual native names cause without cloning its error.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.sample.failure()
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl<P> SourceCoordinatorWriterV1<P> {
    /// Prepays the real append, upper interval and independent Source post.
    ///
    /// This performs no cloning, encoding or IO. Upper bytes describe the
    /// actual private interval owner's compiled construction/Arc peak; neither
    /// those bytes nor the inert original reference grant any native entry.
    ///
    /// # Errors
    /// Retains actual checked representation refusal and fences fresh reuse.
    pub fn prepay_append_interval_once(
        &mut self,
        transaction: &JournalTransaction,
        upper_interval_bytes: usize,
    ) -> Result<(), SourceNativeErrorV1> {
        self.require_append_entry_v1(transaction)?;
        self.prepay_append_interval_inner_v1(transaction, upper_interval_bytes)
    }

    pub(super) fn prepay_append_interval_inner_v1(
        &mut self,
        transaction: &JournalTransaction,
        upper_interval_bytes: usize,
    ) -> Result<(), SourceNativeErrorV1> {
        if self.native_post_active || self.append_prepaid {
            return Err(SourceNativeErrorV1::Closed);
        }
        self.append_upper_interval_bytes = Some(
            upper_interval_bytes.max(self.append_upper_interval_bytes.unwrap_or(0)),
        );
        match self.require_append_representation(transaction) {
            Ok(()) => {
                self.append_prepaid = true;
                Ok(())
            }
            Err(cause) => {
                self.debit_failure = Some(cause);
                self.fenced = true;
                Err(SourceNativeErrorV1::Closed)
            }
        }
    }

    /// Arms the already-funded same-writer post before the upper append body.
    ///
    /// No native observation occurs here. The independently owed finish must
    /// run even when later native debit, encoding or semantic work refuses.
    ///
    /// # Errors
    /// Refuses unhealthy, active or unprepaid entry without creating a new scope.
    pub fn begin_independent_native_post_once(&mut self) -> Result<SourceNativePostOriginalV1, SourceNativeErrorV1> {
        self.require_idle()?;
        self.begin_independent_native_post_inner_v1()
    }

    pub(super) fn begin_independent_native_post_inner_v1(&mut self)
        -> Result<SourceNativePostOriginalV1, SourceNativeErrorV1>
    {
        if self.native_post_active || !self.append_prepaid {
            return Err(SourceNativeErrorV1::Closed);
        }
        let mut sample = WriterCurrentnessOriginalsV1::new();
        sample.begin(true)?;
        self.native_post_active = true;
        Ok(SourceNativePostOriginalV1 {
            identity: Arc::clone(&self.custody),
            sample,
            returned: None,
            settled: false,
        })
    }

    /// Attempts the already-armed Source native post even after body poison.
    ///
    /// # Errors
    /// Retains original native names failure or refuses foreign/repeated work.
    pub fn finish_independent_native_post_once(&self, post: &mut SourceNativePostOriginalV1) -> Result<(), SourceNativeErrorV1> {
        if !self.native_post_active || post.settled || post.returned.is_some()
            || !Arc::ptr_eq(&post.identity, &self.custody)
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        let result = self.physical.observe_names_into(&mut post.sample);
        post.returned = Some(post.sample.finish(result));
        if matches!(post.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(SourceNativeErrorV1::Closed)
        }
    }

    /// Disposes this completed native post after the actual upper posts settle.
    ///
    /// The trusted upper coordinator retains the complete semantic body and
    /// post window. No caller success flag substitutes for that sequencing.
    ///
    /// # Errors
    /// Refuses incomplete, failed, foreign or poisoned work without resetting debt.
    pub fn dispose_native_post_after_upper_posts_once(&mut self, post: &mut SourceNativePostOriginalV1) -> Result<(), SourceNativeErrorV1> {
        self.require_native_post_disposal_v1(post)?;
        self.complete_native_post_disposal_v1(post);
        Ok(())
    }

    pub(super) fn require_native_post_disposal_v1(
        &self,
        post: &SourceNativePostOriginalV1,
    ) -> Result<(), SourceNativeErrorV1> {
        if !self.native_post_active || self.has_native_uncertainty_v1()
            || post.settled || !Arc::ptr_eq(&post.identity, &self.custody)
            || !matches!(post.returned, Some(Ok(()))) || post.failure().is_some()
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        Ok(())
    }

    // The actual positive token holds the same exclusive writer/post borrow
    // from the preceding complete check through upper disposal and this step.
    pub(super) fn complete_native_post_disposal_v1(
        &mut self,
        post: &mut SourceNativePostOriginalV1,
    ) {
        post.sample.settle_positive_once_v1();
        post.settled = true;
        self.native_post_active = false;
        self.append_prepaid = false;
    }
}

impl Drop for SourceNativePostOriginalV1 {
    fn drop(&mut self) {
        if !self.settled {
            // Keep any actual native prefix resident through termination.
            std::process::abort();
        }
    }
}
