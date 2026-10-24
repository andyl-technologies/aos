//! Signs the two selected transfer phases from their same original Source.
//!
//! A genuine pre-context Core claim is mandatory for each phase. The Source
//! keeps its comparison banks and spent state independently from SDK originals;
//! final four-owner journal verification and restoration context remain separate.

use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_transport::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase;

#[path = "restoration_transfer/owner.rs"]
mod owner;
pub(super) use owner::OriginalSourceRestoreTransferAttempt;

use crate::node_admission::{
    OriginalRestorationMappingInputs, OriginalRestorationSigningConstructionInputs,
    OriginalRestorationSigningInputs, OriginalRestorationTransactionClaim,
    OriginalRestorationTransactionInspection, OriginalRestorationTransactionPhase,
};
use crucible_node_transport::envelope::Envelope;
use crucible_node_transport::{
    bodies::{BeginKind, BeginRequest, MethodResult, PrepareRestoreArguments, ResponseShape},
    client::{OriginalFreshRestorePrepareBindingStorageData, OriginalFreshRestoreQuery},
    envelope::Nullable,
    reference_packet::service::complete_restore::{
        PACKET_COMPLETE_RESTORE_ALGORITHM, PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA,
        PACKET_COMPLETE_RESTORE_FEATURE, PacketCompleteRestoreContext,
        PacketCompleteRestoreRequest, transfer::*,
    },
};
use serde::{Deserialize, Serialize};
use std::mem::size_of;

#[path = "restoration_transfer/requests.rs"]
mod requests;

#[path = "restoration_transfer/prepare.rs"]
mod prepare;
#[path = "restoration_transfer/receipts.rs"]
mod receipts;

#[path = "restoration_transfer/commit.rs"]
mod commit;

#[path = "restoration_transfer/evidence.rs"]
mod evidence;
#[path = "restoration_transfer/inputs.rs"]
mod inputs;
pub(crate) use evidence::{OriginalSourceRestoreVerifiedPhase, SourceVerifiedPhase};

#[path = "restoration_transfer/construction.rs"]
mod construction;
pub(crate) use construction::OriginalSourceRestoreSignerConstructionData;

#[path = "restoration_transfer/mapping.rs"]
mod mapping;
#[path = "restoration_transfer/requote.rs"]
mod requote;
