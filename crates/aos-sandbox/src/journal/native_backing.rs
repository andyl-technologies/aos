//! Keeps ordinary native DATA and genuine selected writers in one private owner.
//!
//! Ordinary storage preserves its exact native→index→protected-location drop
//! order. Selected variants retain the actual closed Broker writer; no dummy
//! native, empty shadow index or imported File/tuple substitutes for it. Upper
//! semantic gates remain in the Journal and drive the same named native stages.

use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryHeldJournalV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendV1, CanonicalCoordinatorReadV1, CanonicalWriterReadViewV1,
};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCoordinatorWriterV1;
#[cfg(target_os = "linux")]
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheConsumerReadBorrowV1;

use super::*;

#[cfg(target_os = "linux")]
pub(crate) type ControllerCoordinatorSelectionV1 = runtime_deployment_history::OriginalCompactionSelectionV1;
#[cfg(target_os = "linux")]
pub(super) type Selection = ControllerCoordinatorSelectionV1;
#[cfg(not(target_os = "linux"))]
pub(super) type Selection = ();

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Index = BTreeMap<Vec<u8>, IdempotencyDecision>;
type ControllerWriter = ControllerCoordinatorWriterV1<Selection>;

pub(super) struct OrdinaryJournalNativeV1 {
    pub(super) held: CanonicalOrdinaryHeldJournalV1<Selection, JournalAuthorityInstance>,
    #[cfg(target_os = "linux")]
    pub(super) captured_append: Option<super::native_interval::captured::CapturedAppendOwnerV1>,
}

pub(super) enum JournalNativeBackingV1 {
    Ordinary(OrdinaryJournalNativeV1),
    #[cfg(target_os = "linux")]
    Controller(ControllerWriter),
    #[cfg(target_os = "linux")]
    Root(aos_sandbox_broker::receiving::RootCoordinatorWriterV1<Selection>),
    #[cfg(target_os = "linux")]
    Source(aos_sandbox_source::native::SourceNativeJournalOwnerV1<Selection>),
}

impl Journal {
    /// Borrows the original failed captured or selected native append.
    ///
    /// This diagnostic neither grants health nor extracts the retained body.
    #[must_use]
    pub fn retained_native_append_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.retained_selected_failure_v1()
    }

    /// Prices retained append DATA and both actual native posts for this owner.
    ///
    /// Ordinary uncaptured writers contribute zero. This passive requirement
    /// neither selects a recipe nor grants funding, native entry or authority.
    ///
    /// # Errors
    /// Preserves checked geometry/namespace arithmetic from the installed recipe.
    pub fn captured_append_receiving_demand_v1(&self, encoded_bytes: u64)
        -> Result<aos_sandbox_core::ResourceVector, JournalError>
    {
        #[cfg(target_os = "linux")]
        if let JournalNativeBackingV1::Ordinary(ordinary) = &self.native {
            if let Some(owner) = ordinary.captured_append.as_ref() {
                return owner.append_demand_v1(encoded_bytes);
            }
        }
        Ok(aos_sandbox_core::ResourceVector::ZERO)
    }

    /// Reports only inert retained-DATA storage on this same actual journal.
    #[must_use]
    pub fn has_captured_append_custody_v1(&self) -> bool {
        #[cfg(target_os = "linux")]
        if let JournalNativeBackingV1::Ordinary(ordinary) = &self.native {
            return ordinary.captured_append.is_some();
        }
        false
    }

    // Prefer the actual failed operation to the invocation-wide deny marker.
    // The same Arc remains resident here after any returned diagnostic drops.
    pub(crate) fn retained_selected_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[cfg(target_os = "linux")]
        {
            self.native_interval.as_ref().and_then(|original| original.failure())
                .or_else(|| self.replacement_original.as_ref().and_then(|original| original.failure()))
                .or_else(|| match &self.native {
                    JournalNativeBackingV1::Root(writer) => writer.concrete_failure_v1(),
                    JournalNativeBackingV1::Controller(writer) => writer.retained_append_failure_v1(),
                    JournalNativeBackingV1::Source(writer) => writer.retained_append_failure_v1(),
                    JournalNativeBackingV1::Ordinary(ordinary) => ordinary.captured_append.as_ref().and_then(|owner| owner.failure()),
                })
        }
        #[cfg(not(target_os = "linux"))]
        { None }
    }
}

impl JournalNativeBackingV1 {
    pub(super) fn native_operations(&self)
        -> aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterNativeOperationsV1<'_, Selection>
    {
        use aos_sandbox_broker::canonical_journal::coordinator::CanonicalCoordinatorNativeV1;
        match self {
            Self::Ordinary(ordinary) => ordinary.held.native_operations_v1(),
            #[cfg(target_os = "linux")]
            Self::Controller(writer) => writer.native_operations(),
            #[cfg(target_os = "linux")]
            Self::Root(writer) => writer.native_operations(),
            #[cfg(target_os = "linux")]
            Self::Source(writer) => writer.native_operations(),
        }
    }

    pub(super) fn read_view(&self) -> CanonicalWriterReadViewV1<'_, Selection> {
        match self {
            Self::Ordinary(ordinary) => ordinary.held.coordinator_read_view(),
            #[cfg(target_os = "linux")]
            Self::Controller(writer) => writer.coordinator_read_view(),
            #[cfg(target_os = "linux")]
            Self::Root(writer) => writer.coordinator_read_view(),
            #[cfg(target_os = "linux")]
            Self::Source(writer) => writer.coordinator_read_view(),
        }
    }

    pub(super) fn path(&self) -> &PathBuf {
        self.read_view().path()
    }

    pub(super) fn original_reader(&self)
        -> aos_sandbox_broker::canonical_journal::coordinator::CanonicalCoordinatorReadCursorV1<'_>
    {
        self.read_view().original_reader()
    }

    pub(super) fn captured_reader(&self, length: u64)
        -> aos_sandbox_broker::canonical_journal::coordinator::CanonicalCoordinatorReadCursorV1<'_>
    {
        self.read_view().captured_reader(length)
    }

    pub(super) fn lock_identity<E: From<io::Error>>(&self) -> Result<FileIdentity, E> {
        self.read_view().lock_identity()
    }

    pub(super) fn file_identity<E: From<io::Error>>(&self) -> Result<FileIdentity, E> {
        self.read_view().file_identity()
    }

    /// Borrows the actual ordinary owner for its named readonly observations.
    ///
    /// # Errors
    /// Rejects selected Controller, Root and Source owners without lending them.
    pub(super) fn ordinary_readonly_held_v1(
        &self,
    ) -> Result<&CanonicalOrdinaryHeldJournalV1<Selection, JournalAuthorityInstance>, JournalError> {
        match self {
            Self::Ordinary(ordinary) => Ok(&ordinary.held),
            #[cfg(target_os = "linux")]
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn state(&self) -> &State {
        self.read_view().state()
    }

    pub(super) fn idempotency(&self) -> &Index {
        self.read_view().idempotency_index()
    }

    pub(super) const fn limits(&self) -> JournalLimits {
        match self {
            Self::Ordinary(ordinary) => ordinary.held.limits_data_v1(),
            #[cfg(target_os = "linux")]
            Self::Controller(writer) => writer.limits(),
            #[cfg(target_os = "linux")]
            Self::Root(writer) => writer.limits(),
            #[cfg(target_os = "linux")]
            Self::Source(writer) => writer.limits(),
        }
    }

    pub(super) const fn next_sequence(&self) -> u64 {
        match self {
            Self::Ordinary(ordinary) => ordinary.held.next_sequence_data_v1(),
            #[cfg(target_os = "linux")]
            Self::Controller(writer) => writer.next_sequence(),
            #[cfg(target_os = "linux")]
            Self::Root(writer) => writer.next_sequence(),
            #[cfg(target_os = "linux")]
            Self::Source(writer) => writer.next_sequence(),
        }
    }

    pub(super) fn committed_transactions(&self) -> usize {
        self.read_view().committed_transactions()
    }

    pub(super) fn transaction_ids(&self) -> &BTreeSet<[u8; 16]> {
        self.read_view().transaction_ids()
    }

    pub(super) fn committed_namespaces(&self) -> &BTreeSet<RecordNamespace> {
        self.read_view().committed_namespaces()
    }

    pub(super) fn materialized_bytes(&self) -> usize {
        self.read_view().materialized_bytes()
    }

    pub(super) fn is_poisoned(&self) -> bool {
        match self {
            Self::Ordinary(ordinary) => ordinary.held.read_view_v1().is_poisoned()
                || { #[cfg(target_os = "linux")] { ordinary.captured_append.as_ref().is_some_and(|owner| owner.is_closed()) }
                     #[cfg(not(target_os = "linux"))] { false } },
            #[cfg(target_os = "linux")]
            Self::Controller(writer) => writer.has_native_uncertainty_v1(),
            #[cfg(target_os = "linux")]
            Self::Root(writer) => writer.has_native_uncertainty_v1(),
            #[cfg(target_os = "linux")]
            Self::Source(writer) => writer.has_native_uncertainty_v1(),
        }
    }

    pub(super) fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.read_view().metadata()
    }

    pub(super) fn is_protected(&self) -> bool {
        self.read_view().is_protected()
    }

    pub(super) fn protected_view(&self)
        -> Option<aos_sandbox_broker::canonical_journal::coordinator::CanonicalProtectedReadViewV1<'_, Selection>>
    {
        self.read_view().protected_view()
    }

    pub(super) fn protected_name(&self) -> Option<&str> {
        self.read_view().protected_name()
    }

    pub(super) fn protected_uid(&self) -> Option<u32> {
        self.read_view().protected_uid()
    }

    pub(super) fn poison(&mut self) {
        match self {
            Self::Ordinary(ordinary) => ordinary.held.poison(),
            #[cfg(target_os = "linux")]
            Self::Controller(writer) => {
                aos_sandbox_broker::canonical_journal::coordinator::CanonicalCoordinatorAppendV1::poison(writer);
            }
            #[cfg(target_os = "linux")]
            Self::Root(writer) => {
                aos_sandbox_broker::canonical_journal::coordinator::CanonicalCoordinatorAppendV1::poison(writer);
            }
            #[cfg(target_os = "linux")]
            Self::Source(writer) => {
                writer.poison();
            }
        }
    }
}

impl Journal {
    #[cfg(target_os = "linux")]
    pub(crate) fn require_current_controller_launch_v1(
        &self,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
    ) -> Result<(), JournalError> {
        launch.require_current_controller_v1(self.controller_coordinator_for_bank_read_v1()?)
            .map_err(JournalError::ControllerNative)
    }

    #[cfg(target_os = "linux")]
    pub(in crate::journal) fn from_controller_coordinator_v1(
        writer: ControllerWriter,
        semantic: semantic_remainder::DomainSemanticRemainderDataV1,
        authority_instance: Arc<JournalAuthorityInstance>,
    ) -> Self {
        Self {
            native: JournalNativeBackingV1::Controller(writer),
            root_journal_financial: None,
            native_interval: None,
            provisioning: None, start_admission: None, execution_admission: None,
            operator_recovery: None,
            replacement_original: None,
            cache_policy_gate: None,
            authority_instance,
            source_challenge_history: semantic.source_challenge_history,
            source_original_replay: semantic.source_original_replay,
            source_history_compacted: semantic.source_history_compacted,
            q04_lower_history_present: semantic.q04_lower_history_present,
        }
    }

    #[cfg(target_os = "linux")]
    pub(in crate::journal) fn from_root_coordinator_v1(
        writer: aos_sandbox_broker::receiving::RootCoordinatorWriterV1<Selection>,
        semantic: semantic_remainder::DomainSemanticRemainderDataV1,
        authority_instance: Arc<JournalAuthorityInstance>,
        financial: aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> Self {
        Self {
            native: JournalNativeBackingV1::Root(writer),
            root_journal_financial: Some(financial),
            native_interval: None,
            provisioning: None, start_admission: None, execution_admission: None,
            operator_recovery: None,
            replacement_original: None,
            cache_policy_gate: None,
            authority_instance,
            source_challenge_history: semantic.source_challenge_history,
            source_original_replay: semantic.source_original_replay,
            source_history_compacted: semantic.source_history_compacted,
            q04_lower_history_present: semantic.q04_lower_history_present,
        }
    }

    #[cfg(target_os = "linux")]
    pub(in crate::journal) fn from_source_owner_v1(
        writer: aos_sandbox_source::native::SourceNativeJournalOwnerV1<Selection>,
        semantic: semantic_remainder::DomainSemanticRemainderDataV1,
        authority_instance: Arc<JournalAuthorityInstance>,
    ) -> Self {
        Self {
            native: JournalNativeBackingV1::Source(writer),
            root_journal_financial: None,
            native_interval: None,
            provisioning: None, start_admission: None, execution_admission: None,
            operator_recovery: None,
            replacement_original: None,
            cache_policy_gate: None,
            authority_instance,
            source_challenge_history: semantic.source_challenge_history,
            source_original_replay: semantic.source_original_replay,
            source_history_compacted: semantic.source_history_compacted,
            q04_lower_history_present: semantic.q04_lower_history_present,
        }
    }

    #[cfg(target_os = "linux")]
    pub(in crate::journal) fn source_owner_for_read_v1(&self)
        -> Result<&aos_sandbox_source::native::SourceNativeJournalOwnerV1<Selection>, JournalError>
    {
        match &self.native {
            JournalNativeBackingV1::Source(writer) => Ok(writer),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    /// Selects the actual C borrower or the explicit ordinary comparison route.
    ///
    /// Ordinary compilation keeps its historical allocation policy and cannot
    /// become a protected Controller original. Other selected roles cannot
    /// stand in for C. Request DATA are checked before reaching this gate.
    #[cfg(target_os = "linux")]
    pub(crate) fn cache_consumer_controller_borrow_v1(
        &self,
    ) -> Result<Option<ControllerCacheConsumerReadBorrowV1<'_, Selection>>, JournalError> {
        self.ensure_healthy()?;
        match &self.native {
            JournalNativeBackingV1::Controller(_) => Ok(Some(
                self.controller_coordinator_for_bank_read_v1()?.borrow_cache_consumer_read_v1(),
            )),
            JournalNativeBackingV1::Ordinary(_) => Ok(None),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    /// Borrows the genuine Controller coordinator for fresh readonly checks.
    ///
    /// The caller still performs its existing healthy/profile/launch gates.
    /// This view exposes no mutable native file or imported authority.
    #[cfg(target_os = "linux")]
    pub(crate) fn controller_coordinator_for_bank_read_v1(&self)
        -> Result<&ControllerWriter, JournalError>
    {
        match &self.native {
            JournalNativeBackingV1::Controller(writer) => Ok(writer),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    // Only the existing trusted Controller Journal child can reach this private
    // opaque coordinator. No raw physical, index, location, File or FD escapes.
    #[cfg(target_os = "linux")]
    pub(crate) fn controller_coordinator_for_bank_v1(&mut self) -> Result<&mut ControllerWriter, JournalError> {
        match &mut self.native {
            JournalNativeBackingV1::Controller(writer) => Ok(writer),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl JournalNativeBackingV1 {
    fn ordinary_fixture(&mut self)
        -> &mut CanonicalOrdinaryHeldJournalV1<Selection, JournalAuthorityInstance>
    {
        match self {
            Self::Ordinary(ordinary) => &mut ordinary.held,
            #[cfg(target_os = "linux")]
            _ => panic!("ordinary DATA fixture cannot mutate a genuine selected writer"),
        }
    }

    #[cfg(test)]
    pub(super) fn set_length_for_fixture(&mut self, length: u64) -> io::Result<()> {
        self.ordinary_fixture().set_length_for_fixture_v1(length)
    }

    #[cfg(test)]
    pub(super) fn clone_protected_directory_for_fixture(&self) -> Result<File, JournalError> {
        match self {
            Self::Ordinary(ordinary) => ordinary.held.clone_protected_directory_for_fixture_v1(),
            #[cfg(target_os = "linux")]
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn replace_limits_for_fixture(&mut self, limits: JournalLimits) {
        self.ordinary_fixture().replace_limits_for_fixture_v1(limits);
    }

    pub(super) fn replace_next_sequence_for_fixture(&mut self, sequence: u64) {
        self.ordinary_fixture().replace_next_sequence_for_fixture_v1(sequence);
    }

    pub(super) fn replace_path_for_fixture(&mut self, path: PathBuf) {
        self.ordinary_fixture().replace_path_for_fixture_v1(path);
    }

    pub(super) fn replace_file(&mut self, file: File) {
        self.ordinary_fixture().replace_file_for_fixture_v1(file);
    }

    pub(super) fn apply_mutation(&mut self, record: aos_sandbox_journal::materialized::RecordMutationRef<'_, RecordNamespace>) {
        self.ordinary_fixture().apply_mutation_for_fixture_v1(record);
    }

    pub(super) fn expected_append_length_for_fixture(&self, frames: &[Vec<u8>])
        -> Result<u64, aos_sandbox_journal::framing::FrameError>
    {
        match self {
            Self::Ordinary(ordinary) => ordinary.held.expected_append_length_for_fixture_v1(frames),
            #[cfg(target_os = "linux")]
            _ => panic!("ordinary DATA fixture cannot mutate a genuine selected writer"),
        }
    }

    pub(super) fn append_exact(&mut self, frames: &[Vec<u8>], expected: u64)
        -> Result<u64, aos_sandbox_journal::framing::FrameError>
    {
        self.ordinary_fixture().append_exact_for_fixture_v1(frames, expected)
    }
}

impl Journal {
    /// Measures the same genuine Root writer's independent native names post.
    pub(crate) fn root_names_post_demand_v1(&self)
        -> Result<aos_sandbox_core::ResourceVector, JournalError>
    {
        match &self.native {
            JournalNativeBackingV1::Root(writer) => writer.native_post_demand_v1()
                .map_err(JournalError::RootNative),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn arm_root_names_post_once_v1(
        &self,
    ) -> Result<aos_sandbox_broker::receiving::RootWriterPostOriginalV1, JournalError> {
        match &self.native {
            JournalNativeBackingV1::Root(writer) => writer.arm_native_post_once_v1().map_err(JournalError::RootNative),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn finish_root_names_post_once_v1(
        &self,
        post: &mut aos_sandbox_broker::receiving::RootWriterPostOriginalV1,
    ) -> Result<(), JournalError> {
        match &self.native {
            JournalNativeBackingV1::Root(writer) => writer.finish_native_post_once_v1(post).map_err(JournalError::RootNative),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }
}

// This closed Source projection lends only the genuine coordinator's Delete
// scope. It accepts an actual consumed C loan, never a caller amount, raw File,
// writer tuple or decoded plan. No mutable native coordinator escapes.
#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn borrow_source_for_delete_v1<'scope, 'original>(
        &'scope mut self,
        receiving: &'scope mut aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &Journal,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<aos_sandbox_broker::source_receiving::SourceDeleteScopeV1<'scope, 'original, Selection>, JournalError> {
        self.ensure_healthy()?;
        let source = match &mut self.native {
            JournalNativeBackingV1::Source(source) => source,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        source.borrow_delete_scope_v1(receiving,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile)
            .map_err(JournalError::ControllerNative)
    }

    pub(crate) fn borrow_source_for_execution_v1<'scope, 'original>(
        &'scope mut self,
        receiving: &'scope mut aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &Journal,
        launch: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
        profile: &aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<super::semantic_append::delete::SourceExecutionSemanticScopeV1<'scope, 'original>, JournalError> {
        self.borrow_execution_semantic_scope_v1(receiving, controller, launch, profile)
    }
}

/// Continuously borrows the actual three-file ordinary protected native owner.
///
/// This mechanical DATA borrower exposes no Journal, File, descriptor or writer.
#[doc(hidden)]
pub struct JournalProtectedNativeResidencyV1<'held> {
    journal: &'held Journal,
}

impl JournalProtectedNativeResidencyV1<'_> {
    /// Counts its actual native file, lock file and protected directory.
    #[must_use]
    pub const fn open_files_v1(&self) -> usize { 3 }

    pub(crate) fn matches_v1(&self, actual: &Journal) -> bool {
        std::ptr::eq(self.journal, actual)
    }
}

impl Journal {
    /// Borrows the existing protected ordinary native owner without IO.
    ///
    /// A selected C/R/Source writer cannot be recast as an initial Client
    /// Journal. Actual same-original admission remains at its enclosing loan.
    #[doc(hidden)]
    #[must_use]
    pub fn borrow_protected_native_residency_v1(&self) -> Option<JournalProtectedNativeResidencyV1<'_>> {
        match &self.native {
            JournalNativeBackingV1::Ordinary(ordinary)
                if ordinary.held.read_view_v1().is_protected() && self.retained_selected_failure_v1().is_none() =>
            {
                Some(JournalProtectedNativeResidencyV1 { journal: self })
            }
            _ => None,
        }
    }
}
