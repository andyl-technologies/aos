//! Retains the genuine Source18 phase bank before bootstrap or SDK effects.
//!
//! This owner is distinct from the old import17 transfer bank. Construction
//! binds the same actual Source allocation and its completed prebirth recipe
//! and initial result. Every later signer and SDK handoff must populate this
//! bank under independently admitted rows before performing its effects. A
//! retained bank, a typed receipt or a flag never proves native completion.

use super::PacketCompleteSemanticSource;
use crate::node_contract::RuntimeError;
use crucible_node_contract::{Id, U64};
use crucible_node_provider::{
    bodies::BeginRequest,
    client::{
        OriginalNativeImport18Assignment, OriginalNativeImport18AssignmentStorageData,
        OriginalNativeImport18Bootstrap, OriginalNativeImport18BootstrapConstructionData,
    },
    reference_packet::service::complete_restore::{
        transfer::{PacketCompleteRestoreCommitRequest, PacketCompleteRestorePrepareRequest},
        import18::{
            PacketNativeImport18Binding, PacketNativeImport18InitialFundingData,
            PacketNativeImport18PrebirthRecipeData, PacketNativeImport18InitialFundingHistoryData,
            bootstrap_ack::{
                PacketNativeImport18BootstrapRequest, PacketNativeImport18BootstrapResult,
                PacketNativeImport18BootstrapAckContext, PacketNativeImport18BootstrapAckProof,
                PacketNativeImport18BootstrapAckReceipt,
            },
        },
    },
};
use crucible_node_provider::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use super::retained_values::edition18_tokens::{
    LiteralValue18Data, LiteralValue18TokenAttempt, LiteralValue18TokenAttemptPartialData,
};
use std::{
    cell::{BorrowError, Ref},
    mem::size_of,
    rc::{Rc, Weak},
    thread::ThreadId,
};

#[path = "import18_phase_bank/construction.rs"]
mod construction;
#[path = "import18_phase_bank/history.rs"]
mod history;
#[path = "import18_phase_bank/storage.rs"]
mod storage;

pub use construction::OriginalNativeImport18SourcePhaseBankConstructionData;
pub(super) use history::{
    NativeImport18SourceBankHistoryData, NativeImport18BankHistoryData,
    NativeImport18SourceOwnerHistoryData, NativeImport18SourceOwnerHistoryIter,
    NativeImport18BootstrapHistoryData, NativeImport18LiteralHistoryData,
    NativeImport18BootstrapSdkHistoryData, NativeImport18BootstrapSdkRowHistoryData,
    NativeImport18PhaseHistoryData, NativeImport18SdkHistoryData, NativeImport18SdkRowHistoryData,
};

/// Retains one construction occurrence even if the owner-vector reserve fails.
pub(super) struct NativeImport18SourcePhaseBank {
    row: OriginalNativeImport18SourcePhaseBankConstructionData,
    started: bool,
    retained: bool,
    failed: bool,
    owners: Vec<NativeImport18SourcePhaseOwner>,
}

/// Identifies actual construction progress without issuing any phase claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Retention {
    Retaining,
    Retained,
}

/// Retains the actual immutable birth operands independently of later traffic.
struct NativeImport18SourcePhaseOwner {
    process: u32,
    thread: ThreadId,
    source: Weak<PacketCompleteSemanticSource>,
    recipe: PacketNativeImport18PrebirthRecipeData,
    initial: PacketNativeImport18InitialFundingData,
    retention: Retention,
    bootstrap: BootstrapPartials,
    prepare: PhasePartials,
    commit: PhasePartials,
    prepare_request: Option<PacketCompleteRestorePrepareRequest>,
    commit_request: Option<PacketCompleteRestoreCommitRequest>,
    binding: Option<PacketNativeImport18Binding>,
    sdk_rows: [Option<OriginalNativeImport18AssignmentStorageData>; 2],
    prepare_capsule: Option<OriginalNativeImport18Assignment>,
    input_upload_started: bool,
    input_upload_verified: bool,
    failed: bool,
}

/// Retains actual bootstrap signing inputs independently of an SDK completion.
// The dedicated typed SDK owner remains distinct from any completed witness.
// A future genuine same-Source signer must install it after actual admission.
struct BootstrapPartials {
    sdk_row: Option<OriginalNativeImport18BootstrapConstructionData>,
    sdk_owner: Option<OriginalNativeImport18Bootstrap>,
    started: bool,
    assigned: bool,
    publishing: bool,
    failed: bool,
    request_id: Option<Id>,
    request: Option<PacketNativeImport18BootstrapRequest>,
    context: Option<PacketNativeImport18BootstrapAckContext>,
    proof: Option<PacketNativeImport18BootstrapAckProof>,
    result: Option<PacketNativeImport18BootstrapResult>,
    receipt: Option<PacketNativeImport18BootstrapAckReceipt>,
    literal_attempt: Option<LiteralValue18TokenAttempt>,
    literal: Option<LiteralValue18Data>,
    encoded: Vec<u8>,
}

/// Retains every independently initialized Source formatter/codec prefix.
struct LiteralPartial {
    attempt: Option<LiteralValue18TokenAttempt>,
    literal: Option<LiteralValue18Data>,
    encoded: Vec<u8>,
}

/// Keeps Source signing progress separate from SDK or native completion.
struct PhasePartials {
    request_id: Option<Id>,
    baseline: Option<BeginRequest>,
    normalized: [LiteralPartial; 5],
    started: bool,
    assigned: bool,
    sealed: bool,
    publishing: bool,
    verified: bool,
    failed: bool,
}

impl BootstrapPartials {
    fn new_data() -> Self {
        Self {
            sdk_row: None,
            sdk_owner: None,
            started: false,
            assigned: false,
            publishing: false,
            failed: false,
            request_id: None,
            request: None,
            context: None,
            proof: None,
            result: None,
            receipt: None,
            literal_attempt: None,
            literal: None,
            encoded: Vec::new(),
        }
    }
}

impl LiteralPartial {
    fn new_data() -> Self {
        Self {
            attempt: None,
            literal: None,
            encoded: Vec::new(),
        }
    }
}

impl PhasePartials {
    fn new_data() -> Self {
        Self {
            request_id: None,
            baseline: None,
            normalized: [
                LiteralPartial::new_data(),
                LiteralPartial::new_data(),
                LiteralPartial::new_data(),
                LiteralPartial::new_data(),
                LiteralPartial::new_data(),
            ],
            started: false,
            assigned: false,
            sealed: false,
            publishing: false,
            verified: false,
            failed: false,
        }
    }
}

/// Names the defining bank census plus this forwarding result.
pub(super) fn retained_counter_scratch_data() -> usize {
    storage::retained_counter_scratch_data() + size_of::<usize>()
}
