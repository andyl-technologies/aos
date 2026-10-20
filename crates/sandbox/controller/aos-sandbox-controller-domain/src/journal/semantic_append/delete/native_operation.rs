//! Dispatches genuine Delete and Execution scopes into one existing native append engine.

use super::*;
use aos_sandbox_broker::source_receiving::{SourcePreparedAppendV1, SourceNativeErrorV1};
use aos_sandbox_broker::canonical_journal::append_stages::CanonicalAppendPublishedDataV1;

pub(super) enum SourceSemanticNativeScopeRefV1<'append, 'journal, 'original> {
    Delete(&'append mut SourceDeleteScopeV1<'journal, 'original, Selection>),
    Execution(&'append mut aos_sandbox_broker::source_receiving::SourceExecutionScopeV1<'journal, 'original, Selection>),
}

impl<'append, 'journal, 'original> SourceSemanticNativeScopeRefV1<'append, 'journal, 'original> {
    pub(super) fn semantic_read_view_v1(&self) -> CanonicalWriterReadViewV1<'_, Selection> {
        match self { Self::Delete(scope) => scope.semantic_read_view_v1(), Self::Execution(scope) => scope.semantic_read_view_v1() }
    }

    pub(super) fn durable_end_data_v1(&self) -> u64 {
        match self { Self::Delete(scope) => scope.durable_end_data_v1(), Self::Execution(scope) => scope.durable_end_data_v1() }
    }

    pub(super) fn enter_semantic_append_once_v1(
        self, controller: &mut aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<Selection>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction, semantic: ResourceVector, complete: ResourceVector, bytes: usize,
    ) -> Result<SourceSemanticNativeAppendV1<'append, 'journal, 'original>, aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1> {
        match self {
            Self::Delete(scope) => scope.enter_delete_semantic_append_once_v1(controller, launch, profile, transaction, semantic, complete, bytes).map(SourceSemanticNativeAppendV1::Delete),
            Self::Execution(scope) => scope.enter_execution_environment_semantic_append_once_v1(controller, launch, profile, transaction, semantic, complete, bytes).map(SourceSemanticNativeAppendV1::Execution),
        }
    }
}

pub(super) enum SourceSemanticNativeAppendV1<'append, 'journal, 'original> {
    Delete(SourceDeleteAppendOriginalV1<'append, 'journal, 'original, Selection>),
    Execution(aos_sandbox_broker::source_receiving::SourceExecutionEnvironmentAppendOriginalV1<'append, 'journal, 'original, Selection>),
}

macro_rules! native_append_delegate {
    ($receiver:expr, |$native:ident| $body:expr) => {
        match $receiver { SourceSemanticNativeAppendV1::Delete($native) => $body, SourceSemanticNativeAppendV1::Execution($native) => $body }
    };
}

impl<'append, 'journal, 'original> SourceSemanticNativeAppendV1<'append, 'journal, 'original> {
    pub(super) fn semantic_read_view_v1(&self)
        -> aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, Selection>
    {
        native_append_delegate!(self, |native| native.semantic_read_view_v1())
    }

    pub(super) fn prepare_semantic_append_once_v1(&mut self, transaction: &JournalTransaction)
        -> Result<(), SourceNativeErrorV1>
    {
        native_append_delegate!(self, |native| native.prepare_semantic_append_once_v1(transaction))
    }

    pub(super) fn semantic_metadata_length_once_v1(&mut self) -> Result<u64, SourceNativeErrorV1> {
        native_append_delegate!(self, |native| native.semantic_metadata_length_once_v1())
    }

    pub(super) fn poison_after_semantic_failure_v1(&mut self) {
        native_append_delegate!(self, |native| native.poison_after_semantic_failure_v1())
    }

    pub(super) fn prepared_v1(&self) -> Option<&SourcePreparedAppendV1> {
        native_append_delegate!(self, |native| native.prepared_v1())
    }

    pub(super) fn readback_published_once_v1(&mut self, output: &mut [u8])
        -> Result<(), SourceNativeErrorV1>
    {
        native_append_delegate!(self, |native| native.readback_published_once_v1(output))
    }

    pub(super) fn coordinates_once_v1(&mut self) -> Result<(u64, u64), SourceNativeErrorV1> {
        native_append_delegate!(self, |native| native.coordinates_once_v1())
    }

    pub(super) fn expected_length_once_v1(&mut self) -> Result<u64, SourceNativeErrorV1> {
        native_append_delegate!(self, |native| native.expected_length_once_v1())
    }

    pub(super) fn append_once_v1(&mut self) -> Result<u64, SourceNativeErrorV1> {
        native_append_delegate!(self, |native| native.append_once_v1())
    }

    pub(super) fn apply_next_record_once_v1(&mut self) -> Result<bool, SourceNativeErrorV1> {
        native_append_delegate!(self, |native| native.apply_next_record_once_v1())
    }

    pub(super) fn publish_once_v1(&mut self) -> Result<CanonicalAppendPublishedDataV1, SourceNativeErrorV1> {
        native_append_delegate!(self, |native| native.publish_once_v1())
    }

    pub(super) fn finish_native_once_v1(&mut self) -> Result<(), SourceNativeErrorV1> {
        native_append_delegate!(self, |native| native.finish_native_once_v1())
    }

    pub(super) fn primary_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        native_append_delegate!(self, |native| native.primary_failure_v1())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        native_append_delegate!(self, |native| native.failure())
    }

    pub(super) fn finish_outer_scope_once_v1(&mut self,
        controller: &mut aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1<Selection>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1> {
        native_append_delegate!(self, |native| native.finish_outer_scope_once_v1(controller, launch, profile))
    }

    pub(super) fn prepare_positive_disposal_v1<'disposal>(&'disposal mut self)
        -> Result<SourceSemanticNativeDisposalV1<'disposal, 'append, 'journal, 'original>, aos_sandbox_broker::source_receiving::SourceNativeErrorV1>
    {
        match self {
            Self::Delete(native) => native.prepare_positive_disposal_v1().map(SourceSemanticNativeDisposalV1::Delete),
            Self::Execution(native) => native.prepare_positive_disposal_v1().map(SourceSemanticNativeDisposalV1::Execution),
        }
    }
}

pub(super) enum SourceSemanticNativeDisposalV1<'disposal, 'append, 'journal, 'original> {
    Delete(SourceDeleteAppendDisposalV1<'disposal, 'append, 'journal, 'original, Selection>),
    Execution(aos_sandbox_broker::source_receiving::SourceExecutionEnvironmentAppendDisposalV1<'disposal, 'append, 'journal, 'original, Selection>),
}

impl SourceSemanticNativeDisposalV1<'_, '_, '_, '_> {
    pub(super) fn complete_after_disposal_v1(self) {
        match self { Self::Delete(native) => native.complete_after_disposal_v1(), Self::Execution(native) => native.complete_after_disposal_v1() }
    }
}
