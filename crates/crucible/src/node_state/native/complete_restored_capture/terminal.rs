//! Names independently admitted pure-verifier constructors in actual reader order.
//!
//! These copyable accounting facts do not authenticate a Source, parent archive,
//! Runtime or World. The actual signed readers issue steps at their constructor
//! boundaries; the live Window separately retains nonrenewing numeric debits.

use super::*;
use crucible_node_contract::U64;
use crucible_node_provider::protocol_snapshot::restored_settled17::NativeCold17Work;

/// Identifies one actual member of the closed three-Source cohort as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredArchive17SourceIndex(u8);

impl RestoredArchive17SourceIndex {
    pub(crate) fn from_data(value: usize) -> Result<Self, StateError> {
        if value >= 3 {
            return Err(refused(
                "terminal Source index is outside the actual cohort",
            ));
        }
        Ok(Self(value as u8))
    }

    pub(crate) fn index_data(self) -> usize {
        self.0 as usize
    }
}

/// Names the finite constructor families, with Parent rows remaining append-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestoredArchive17ValidationStage {
    MetadataDag,
    ContentClosure,
    Administrative,
    Coordinator,
    CoordinatorAncestry,
    Host,
    RuntimeIdentity,
    SchedulingIdentity,
    OwnerReceipts,
    Journal(RestoredArchive17SourceIndex),
    Controller(RestoredArchive17SourceIndex),
    SdkCapture(RestoredArchive17SourceIndex),
    Native(RestoredArchive17SourceIndex),
    SemanticEnvelope(RestoredArchive17SourceIndex),
    Node(RestoredArchive17SourceIndex),
    Parent(RestoredArchive17SourceIndex),
    Source(RestoredArchive17SourceIndex),
    FinalConjunction,
}

impl RestoredArchive17ValidationStage {
    pub(crate) const STAGE_COUNT: usize = 34;

    pub(crate) fn slot_data(self) -> usize {
        match self {
            Self::MetadataDag => 0,
            Self::ContentClosure => 1,
            Self::Administrative => 2,
            Self::Coordinator => 3,
            Self::CoordinatorAncestry => 4,
            Self::Host => 5,
            Self::RuntimeIdentity => 6,
            Self::SchedulingIdentity => 7,
            Self::OwnerReceipts => 8,
            Self::Journal(index) => 9 + index.index_data() * 6,
            Self::Controller(index) => 10 + index.index_data() * 6,
            Self::SdkCapture(index) => 11 + index.index_data() * 6,
            Self::Native(index) => 12 + index.index_data() * 6,
            Self::SemanticEnvelope(index) => 13 + index.index_data() * 6,
            Self::Node(index) => 14 + index.index_data() * 6,
            Self::Parent(index) => 27 + index.index_data(),
            Self::Source(index) => 30 + index.index_data(),
            Self::FinalConjunction => 33,
        }
    }

    pub(crate) fn source_index_data(self) -> Option<RestoredArchive17SourceIndex> {
        match self {
            Self::Journal(index)
            | Self::Controller(index)
            | Self::SdkCapture(index)
            | Self::Native(index)
            | Self::SemanticEnvelope(index)
            | Self::Node(index)
            | Self::Parent(index)
            | Self::Source(index) => Some(index),
            _ => None,
        }
    }

    pub(crate) fn is_parent_data(self) -> bool {
        matches!(self, Self::Parent(_))
    }
}

/// Identifies the actual parent constructor without confusing tree depth with time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestoredArchive17ParentWork {
    Slot,
    ScopeProof,
    ScopeHold,
    ScopeBuild,
    IndexDecode,
    Inventory,
    ManifestDecode,
    ManifestValidate,
    CoordinatorDecode,
    HostDecode,
    RuntimeDecode,
    SchedulingDecode,
    AdministrativeDecode,
    Initial15(RestoredArchive17Initial15Work),
    Journal,
    SdkCapture,
    SemanticEnvelope,
    Native,
    Controller,
    Node,
    Source,
    Join,
}

/// Names actual immutable role decoders inside the initial15 parent reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestoredArchive17Initial15Role {
    Provenance,
    Plan,
    Descriptors,
    Contracts,
    Fixtures,
    Coordinator,
    Runtime,
    Scheduling,
    Administrative,
}

/// Names an independently copied qualification-reference role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestoredArchive17Initial15QualificationRole {
    Descriptors,
    Contracts,
    Fixtures,
}

/// Names actual separately admitted initial15 constructors, including members.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestoredArchive17Initial15Work {
    Header,
    RoleDecode(RestoredArchive17Initial15Role),
    RoleTyped(RestoredArchive17Initial15Role),
    QualificationReference(RestoredArchive17Initial15QualificationRole),
    LaunchDecode(RestoredArchive17SourceIndex),
    LaunchValidate(RestoredArchive17SourceIndex),
    RuntimeJoin,
    ProtocolJournal(RestoredArchive17SourceIndex),
    ProtocolPrepare(RestoredArchive17SourceIndex),
    ProtocolReconstruct,
    SemanticDecode(RestoredArchive17SourceIndex),
    SemanticJoin(RestoredArchive17SourceIndex),
}

/// Stores the exact closed Index3 full-reference identity without allocating.
///
/// Algorithm, domain and media type are fixed by the defining format and checked
/// when this DATA is created. The complete length and lowercase digest remain;
/// semantic family, owner and parent-key validation still belong to the reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredArchive17ParentIdentity {
    length: U64,
    digest: [u8; 64],
}

impl RestoredArchive17ParentIdentity {
    pub(crate) fn from_reference_data(reference: &ContentRef) -> Result<Self, StateError> {
        if reference.hash.algorithm != "blake3-256"
            || reference.hash.domain != "cnp.blob.v1"
            || reference.media_type != "application/vnd.crucible.native-signed-index-body.v3+json"
            || reference.length.get() == 0
            || reference.hash.digest.len() != 64
            || !reference
                .hash
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refused(
                "terminal parent identity is not an exact closed Index3 fullref",
            ));
        }
        Ok(Self {
            length: reference.length,
            digest: reference
                .hash
                .digest
                .as_bytes()
                .try_into()
                .map_err(|_| refused("terminal parent digest extent"))?,
        })
    }
}

/// Names one actual bounded parent occurrence and its constructor kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredArchive17ParentStep {
    depth: usize,
    identity: RestoredArchive17ParentIdentity,
    work: RestoredArchive17ParentWork,
}

impl RestoredArchive17ParentStep {
    pub(crate) fn depth_data(self) -> usize {
        self.depth
    }
    pub(crate) fn identity_data(self) -> RestoredArchive17ParentIdentity {
        self.identity
    }
    pub(crate) fn work_data(self) -> RestoredArchive17ParentWork {
        self.work
    }
}

/// Names an actual constructor boundary, never a reusable stage allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredArchive17ValidationStep {
    stage: RestoredArchive17ValidationStage,
    parent: Option<RestoredArchive17ParentStep>,
    native_work: Option<NativeCold17Work>,
}

impl RestoredArchive17ValidationStep {
    pub(crate) fn ordinary_data(
        stage: RestoredArchive17ValidationStage,
    ) -> Result<Self, StateError> {
        if stage.is_parent_data() {
            return Err(refused(
                "terminal parent step requires exact ancestry identity",
            ));
        }
        if matches!(stage, RestoredArchive17ValidationStage::Native(_)) {
            return Err(refused(
                "terminal native step requires actual defining constructor work",
            ));
        }
        Ok(Self {
            stage,
            parent: None,
            native_work: None,
        })
    }

    pub(crate) fn native_data(
        source: RestoredArchive17SourceIndex,
        work: NativeCold17Work,
    ) -> Self {
        Self {
            stage: RestoredArchive17ValidationStage::Native(source),
            parent: None,
            native_work: Some(work),
        }
    }

    pub(crate) fn native_work_data(self) -> Option<NativeCold17Work> {
        self.native_work
    }

    pub(crate) fn parent_data(
        source: RestoredArchive17SourceIndex,
        depth: usize,
        reference: &ContentRef,
        work: RestoredArchive17ParentWork,
    ) -> Result<Self, StateError> {
        Ok(Self {
            stage: RestoredArchive17ValidationStage::Parent(source),
            parent: Some(RestoredArchive17ParentStep {
                depth,
                identity: RestoredArchive17ParentIdentity::from_reference_data(reference)?,
                work,
            }),
            native_work: None,
        })
    }

    pub(crate) fn stage_data(self) -> RestoredArchive17ValidationStage {
        self.stage
    }
    pub(crate) fn parent_step_data(self) -> Option<RestoredArchive17ParentStep> {
        self.parent
    }

    pub(crate) fn authenticate_transition_data(
        self,
        previous: Option<Self>,
    ) -> Result<(), StateError> {
        if self.native_work.is_some()
            && !matches!(self.stage, RestoredArchive17ValidationStage::Native(_))
        {
            return Err(refused(
                "terminal native work crossed its actual constructor bucket",
            ));
        }
        if self.stage.is_parent_data() != self.parent.is_some() {
            return Err(refused("terminal step lost its actual parent identity"));
        }
        if let Some(previous) = previous {
            if self.stage.slot_data() < previous.stage.slot_data()
                || self.stage.slot_data() > previous.stage.slot_data() + 1
                || (self.stage.slot_data() == previous.stage.slot_data()
                    && !self.stage.is_parent_data()
                    && !(self.native_work.is_some() && previous.native_work.is_some()))
            {
                return Err(refused("terminal constructor stage repeated or regressed"));
            }
        } else if self.stage != RestoredArchive17ValidationStage::MetadataDag {
            return Err(refused(
                "terminal constructor sequence omitted its actual initial stage",
            ));
        }
        let previous_native_work = previous
            .filter(|previous| previous.stage == self.stage)
            .and_then(|previous| previous.native_work);
        if let Some(work) = self.native_work {
            if !work.follows_data(previous_native_work) {
                return Err(refused(
                    "terminal native constructor omitted or repeated defining work",
                ));
            }
        }
        if let Some(previous) = previous {
            if previous.stage != self.stage
                && previous
                    .native_work
                    .is_some_and(|work| !work.is_final_data())
            {
                return Err(refused(
                    "terminal native constructor left an incomplete graph pair",
                ));
            }
        }
        // The Window also rejects an exact duplicate parent key against its
        // entire retained ledger. Signed depth/parent correspondence is checked
        // by the defining reader, rather than inferred from stage progression.
        Ok(())
    }
}

/// Bounds quote work beside every still-live previously decoded cache owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredArchive17ValidationPrewalkData {
    step: RestoredArchive17ValidationStep,
    prior_cache: usize,
    transient: usize,
    scratch: usize,
}

impl RestoredArchive17ValidationPrewalkData {
    pub(crate) fn new_data(
        step: RestoredArchive17ValidationStep,
        prior_cache: usize,
        transient: usize,
        scratch: usize,
    ) -> Result<Self, StateError> {
        let result = Self {
            step,
            prior_cache,
            transient,
            scratch,
        };
        result.outer_transient_bytes_data()?;
        Ok(result)
    }
    pub(crate) fn step_data(self) -> RestoredArchive17ValidationStep {
        self.step
    }
    pub(crate) fn prior_cache_retained_bytes_data(self) -> usize {
        self.prior_cache
    }
    pub(crate) fn quote_transient_bytes_data(self) -> usize {
        self.transient
    }
    pub(crate) fn counter_scratch_bytes_data(self) -> usize {
        self.scratch
    }
    pub(crate) fn outer_transient_bytes_data(self) -> Result<usize, StateError> {
        checked_sum(&[self.prior_cache, self.transient, self.scratch])
    }
}

/// Bounds one actual constructor with complete prior-cache coexistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredArchive17ValidationConstructionData {
    step: RestoredArchive17ValidationStep,
    prior_cache: usize,
    retained_growth: usize,
    transient: usize,
    scratch: usize,
}

impl RestoredArchive17ValidationConstructionData {
    pub(crate) fn new_data(
        step: RestoredArchive17ValidationStep,
        prior_cache: usize,
        retained_growth: usize,
        transient: usize,
        scratch: usize,
    ) -> Result<Self, StateError> {
        let result = Self {
            step,
            prior_cache,
            retained_growth,
            transient,
            scratch,
        };
        result.outer_transient_bytes_data()?;
        Ok(result)
    }
    pub(crate) fn step_data(self) -> RestoredArchive17ValidationStep {
        self.step
    }
    pub(crate) fn prior_cache_retained_bytes_data(self) -> usize {
        self.prior_cache
    }
    pub(crate) fn maximum_new_retained_bytes_data(self) -> usize {
        self.retained_growth
    }
    pub(crate) fn constructor_transient_bytes_data(self) -> usize {
        self.transient
    }
    pub(crate) fn counter_scratch_bytes_data(self) -> usize {
        self.scratch
    }
    pub(crate) fn maximum_cache_retained_bytes_data(self) -> Result<usize, StateError> {
        checked_sum(&[self.prior_cache, self.retained_growth])
    }
    pub(crate) fn outer_transient_bytes_data(self) -> Result<usize, StateError> {
        checked_sum(&[
            self.prior_cache,
            self.retained_growth,
            self.transient,
            self.scratch,
        ])
    }
}

/// Borrows the real writer's independently funded terminal phase boundary.
///
/// Implementations retain each numeric phase in the same live Window, release
/// its private mutable bank loan and perform genuine full observation before
/// returning. The pure validator never retains this object or serializes it.
pub(crate) trait RestoredArchive17ValidationAdmission {
    fn begin_stage_data(
        &self,
        prewalk: RestoredArchive17ValidationPrewalkData,
    ) -> Result<(), StateError>;
    fn construct_stage_data(
        &self,
        row: RestoredArchive17ValidationConstructionData,
    ) -> Result<(), StateError>;
    fn finish_stage_data(
        &self,
        step: RestoredArchive17ValidationStep,
        actual_cache_retained: usize,
    ) -> Result<(), StateError>;
}

fn checked_sum(values: &[usize]) -> Result<usize, StateError> {
    values.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| refused("terminal constructor accounting overflow"))
    })
}

#[cfg(test)]
mod controls {
    use super::*;

    #[test]
    fn source_indices_and_actual_constructor_order_are_closed() {
        assert!(RestoredArchive17SourceIndex::from_data(3).is_err());
        let first = RestoredArchive17SourceIndex::from_data(0).unwrap();
        let last = RestoredArchive17SourceIndex::from_data(2).unwrap();
        assert_eq!(
            RestoredArchive17ValidationStage::Journal(first).slot_data(),
            9
        );
        assert_eq!(
            RestoredArchive17ValidationStage::Controller(first).slot_data(),
            10
        );
        assert_eq!(
            RestoredArchive17ValidationStage::SdkCapture(first).slot_data(),
            11
        );
        assert_eq!(
            RestoredArchive17ValidationStage::Native(first).slot_data(),
            12
        );
        assert_eq!(
            RestoredArchive17ValidationStage::Source(last).slot_data(),
            32
        );
        assert_eq!(
            RestoredArchive17ValidationStage::FinalConjunction.slot_data(),
            33
        );
        assert_eq!(
            RestoredArchive17ValidationStage::Journal(
                RestoredArchive17SourceIndex::from_data(1).unwrap()
            )
            .slot_data(),
            15
        );
        assert_eq!(
            RestoredArchive17ValidationStage::Parent(first).slot_data(),
            27
        );
        assert_eq!(
            RestoredArchive17ValidationStage::Source(first).slot_data(),
            30
        );
        assert_eq!(RestoredArchive17ValidationStage::STAGE_COUNT, 34);
    }

    #[test]
    fn constructors_cannot_skip_repeat_or_backdate_numeric_work() {
        let initial = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::MetadataDag,
        )
        .unwrap();
        let next = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::ContentClosure,
        )
        .unwrap();
        let skipped = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::Administrative,
        )
        .unwrap();
        assert!(initial.authenticate_transition_data(None).is_ok());
        assert!(next.authenticate_transition_data(Some(initial)).is_ok());
        assert!(skipped.authenticate_transition_data(Some(initial)).is_err());
        assert!(initial.authenticate_transition_data(Some(initial)).is_err());
        assert!(initial.authenticate_transition_data(Some(next)).is_err());
        assert!(
            RestoredArchive17ValidationPrewalkData::new_data(initial, usize::MAX, 1, 0).is_err()
        );
        assert!(
            RestoredArchive17ValidationConstructionData::new_data(initial, usize::MAX, 1, 0, 0)
                .is_err()
        );
    }

    #[test]
    fn native_constructors_follow_the_defining_sequence_before_leaving_the_bucket() {
        let source = RestoredArchive17SourceIndex::from_data(0).unwrap();
        let before = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::SdkCapture(source),
        )
        .unwrap();
        let after = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::SemanticEnvelope(source),
        )
        .unwrap();
        let works = [
            NativeCold17Work::Framing,
            NativeCold17Work::RawInputs,
            NativeCold17Work::BeforeGraphBanks,
            NativeCold17Work::BeforeGraphTargets,
            NativeCold17Work::AfterGraphBanks,
            NativeCold17Work::AfterGraphTargets,
            NativeCold17Work::OutputPairQuote,
            NativeCold17Work::OutputPair,
            NativeCold17Work::RestorationHoldQuote,
            NativeCold17Work::RestorationHold,
        ];
        assert!(
            RestoredArchive17ValidationStep::ordinary_data(
                RestoredArchive17ValidationStage::Native(source),
            )
            .is_err()
        );
        let mut previous = before;
        for (index, work) in works.iter().copied().enumerate() {
            let step = RestoredArchive17ValidationStep::native_data(source, work);
            assert!(step.authenticate_transition_data(Some(previous)).is_ok());
            assert!(step.authenticate_transition_data(Some(step)).is_err());
            if index + 1 < works.len() {
                assert!(after.authenticate_transition_data(Some(step)).is_err());
            }
            previous = step;
        }
        assert!(after.authenticate_transition_data(Some(previous)).is_ok());
        let skipped = RestoredArchive17ValidationStep::native_data(
            source,
            NativeCold17Work::BeforeGraphBanks,
        );
        assert!(skipped.authenticate_transition_data(Some(before)).is_err());
    }

    #[test]
    fn parent_key_preserves_full_fixed_media_identity_without_a_grant() {
        let mut reference = crucible_node_contract::canonical::content_ref(
            b"actual-data-only",
            "application/vnd.crucible.native-signed-index-body.v3+json",
        )
        .unwrap();
        let first = RestoredArchive17ParentIdentity::from_reference_data(&reference).unwrap();
        reference.length = U64::new(reference.length.get() + 1);
        assert_ne!(
            first,
            RestoredArchive17ParentIdentity::from_reference_data(&reference).unwrap()
        );
        reference.media_type = "application/json".to_owned();
        assert!(RestoredArchive17ParentIdentity::from_reference_data(&reference).is_err());
    }
}
