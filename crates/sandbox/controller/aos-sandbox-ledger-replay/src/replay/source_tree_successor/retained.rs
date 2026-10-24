//! Holds reached Source replay-family work at its original Native call.
//!
//! These are comparison DATA destinations. The genuine Source receiving loan
//! pays their representation before entry; they provide no IO or authority.

use super::*;
use crate::replay::source_tree_genesis::{SourceGenesisRowsV1};
use crate::replay::source_tree_genesis::SourceGenesisRowsOriginalsV1;

pub type SourceFamilySinksV1<'a, E, H, R> = (
    Option<&'a mut Option<Option<SourceGenesisRowsV1>>>,
    Option<&'a mut Option<SourceFirstSuccessorRowsV2>>,
    Option<&'a mut Option<SourceFirstSuccessorReceiptV2>>,
    Option<&'a mut Option<SourceFirstSuccessorAckV2>>,
    Option<&'a mut Option<SourceGenesisRowsV1>>,
    Option<&'a mut SourceGenesisRowsOriginalsV1<E, R>>,
    Option<&'a mut Option<RootFirstSourceSuccessorFloorV2>>,
    Option<&'a mut Option<ControllerFirstSourceSuccessorAnchoredV2>>,
    Option<&'a mut crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<E, H, R>>,
);

pub struct SourceFamilyOriginalsV1<E = JournalError, H = DomainLedgerDataError, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    pub input_genesis: Option<Option<SourceGenesisRowsV1>>,
    pub rows: Option<SourceFirstSuccessorRowsV2>,
    pub receipt: Option<SourceFirstSuccessorReceiptV2>,
    pub ack: Option<SourceFirstSuccessorAckV2>,
    pub genesis: Option<SourceGenesisRowsV1>,
    pub genesis_rows: SourceGenesisRowsOriginalsV1<E, R>,
    pub floor: Option<RootFirstSourceSuccessorFloorV2>,
    pub anchored: Option<ControllerFirstSourceSuccessorAnchoredV2>,
    pub members: crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<E, H, R>,
}

impl<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceFamilyOriginalsV1<E, H, R> {
    pub fn new() -> Self {
        Self {
            input_genesis: None,
            rows: None,
            receipt: None,
            ack: None,
            genesis: None,
            genesis_rows: SourceGenesisRowsOriginalsV1::new(),
            floor: None,
            anchored: None,
            members: crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1::<E, H, R>::new(),
        }
    }
}


impl<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceFamilyOriginalsV1<E, H, R> {
    pub fn loan_footprint_v1() -> Option<(usize, usize)> {
        use std::mem::size_of;
        let bytes = size_of::<SourceFamilySinksV1<'static, E, H, R>>()
            .checked_add(size_of::<Option<&'static mut Self>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceFirstSuccessorReceiptV2>>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceFirstSuccessorAckV2>>>())?
            .checked_add(size_of::<Option<&'static mut Option<RootFirstSourceSuccessorFloorV2>>>())?
            .checked_add(size_of::<Option<&'static mut Option<ControllerFirstSourceSuccessorAnchoredV2>>>())?
            .checked_add(size_of::<Option<&'static mut crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<E, H, R>>>())?;
        Some((bytes, 9 + 1 + 5))
    }

    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
        use std::mem::size_of;
        let (genesis_bytes, genesis_cells) = SourceGenesisRowsOriginalsV1::<E, R>::fixed_footprint_v1()?;
        let (member_bytes, member_cells) = crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(crate::replay::phase_records::first_source_successor_fixed_codec_peak_bytes_v1()?)?
            .checked_add(genesis_bytes.checked_sub(size_of::<SourceGenesisRowsOriginalsV1<E, R>>().checked_mul(2)?)?)?
            .checked_add(member_bytes.checked_sub(size_of::<crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, Option<SourceGenesisRowsV1>>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorRowsV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorReceiptV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorAckV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceGenesisRowsV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, RootFirstSourceSuccessorFloorV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, ControllerFirstSourceSuccessorAnchoredV2>>())?
            .checked_add(Self::loan_footprint_v1()?.0)?;
        // Nine fields, nested genesis/member owners, seven two-field guards,
        // three three-root input/genesis/successor family namespaces.
        Some((bytes, 9usize.checked_add(genesis_cells)?.checked_add(member_cells)?.checked_add(7 * 2 + 3 * 3)?.checked_add(Self::loan_footprint_v1()?.1)?))
    }
}

pub struct SourceReplayFamilyOriginalsV1<E = JournalError, H = DomainLedgerDataError, R = crate::genesis::SourceGenesisReceiptDataErrorV1> {
    pub selected: Option<Option<SourceFirstSuccessorPendingV2>>,
    pub decoded_genesis: Option<SourceGenesisRowsV1>,
    pub genesis: SourceGenesisRowsOriginalsV1<E, R>,
    pub family: SourceFamilyOriginalsV1<E, H, R>,
    pub result: Option<Result<(), E>>,
    pub closed: Option<E>,
    pub entered: bool,
}

impl<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static> SourceReplayFamilyOriginalsV1<E, H, R> {
    pub fn new() -> Self {
        Self {
            selected: None,
            decoded_genesis: None,
            genesis: SourceGenesisRowsOriginalsV1::new(),
            family: SourceFamilyOriginalsV1::new(),
            result: None,
            closed: None,
            entered: false,
        }
    }

    pub fn observe_once(&mut self, state: &State) -> Result<(), E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        let result = replay_family_with_originals(state, Some(self));
        self.result = Some(match result {
            Ok(family) => {
                // Match replay_rows: genesis ends at into_successor, then the
                // completed successor map ends at the unit-result boundary.
                drop(family.into_successor());
                Ok(())
            }
            Err(cause) => Err(cause),
        });
        match &self.result {
            Some(Ok(())) => Ok(()),
            _ => Err(E::from(JournalError::ProtectedBoundary)),
        }
    }

    pub fn failure(&self) -> Option<&E> {
        self.genesis.failure()
            .or_else(|| self.family.genesis_rows.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.closed.as_ref())
    }

    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.genesis.cause()
            .or_else(|| self.family.genesis_rows.cause())
            .or_else(|| self.family.members.failure())
            .or_else(|| self.failure().map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    /// Prices lazy diagnostic ownership beside the unchanged constructor peak.
    ///
    /// The existing fixed footprint covers the constructor's nested pieces
    /// and returned value. The Box adds a distinct resident pointee before
    /// that value moves, plus its optional handle and allocation-layout
    /// carrier. No constructor placement or move elision is assumed.
    /// These are bytes, not namespace entries.
    /// This DATA neither pays an allocation nor supplies a replay permit.
    #[must_use]
    pub fn boxed_footprint_v1() -> Option<(usize, usize)> {
        let (bytes, cells) = Self::fixed_footprint_v1()?;
        let bytes = bytes
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(std::mem::size_of::<Option<Box<Self>>>())?
            .checked_add(std::mem::size_of::<std::alloc::Layout>())?;
        Some((bytes, cells))
    }

    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
        use std::mem::size_of;

        let (genesis_bytes, genesis_cells) = SourceGenesisRowsOriginalsV1::<E, R>::fixed_footprint_v1()?;
        let (member_bytes, member_cells) = crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        // Self includes both nested destinations. Count only their actual guard
        // temporaries again, plus construction and residence of this capsule.
        let genesis_temporaries = genesis_bytes
            .checked_sub(size_of::<SourceGenesisRowsOriginalsV1<E, R>>().checked_mul(2)?)?
            .checked_mul(2)?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(crate::replay::phase_records::first_source_successor_fixed_codec_peak_bytes_v1()?)?
            .checked_add(genesis_temporaries)?
            .checked_add(size_of::<CaptureOnDropV1<'static, Option<SourceFirstSuccessorPendingV2>>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceGenesisRowsV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, Option<SourceGenesisRowsV1>>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorRowsV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorReceiptV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceFirstSuccessorAckV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, RootFirstSourceSuccessorFloorV2>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, ControllerFirstSourceSuccessorAnchoredV2>>())?
            .checked_add(member_bytes.checked_sub(size_of::<crate::replay::tree_lineage::SourceSuccessorMembersOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(SourceFamilyOriginalsV1::<E, H, R>::loan_footprint_v1()?.0)?;
        // 7 replay controls/destinations, 9 family destinations, two complete
        // genesis reservoirs, 8 two-field guards, and 4 three-root family
        // namespaces (input, current, replay genesis and successor). Maps and bytes
        // remain charged by the reached-row supplier before semantic replay.
        let cells = 7usize.checked_add(9)?
            .checked_add(member_cells)?
            .checked_add(genesis_cells.checked_mul(2)?)?
            .checked_add(8 * 2)?
            .checked_add(4 * 3)?.checked_add(SourceFamilyOriginalsV1::<E, H, R>::loan_footprint_v1()?.1)?;
        Some((bytes, cells))
    }
}
