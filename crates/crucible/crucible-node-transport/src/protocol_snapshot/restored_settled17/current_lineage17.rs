//! Borrows exact signed-lineage fields after the full immutable Boot wire walk.
//!
//! Every loan originates in the same source-order pass that checks the complete
//! capacity and alias rosters. A loan carries its actual metadata cursor and end
//! position. The narrow decoder may retain its concrete signed DTOs independently;
//! it never reconstructs a historical Boot, imported heap or native capability.

use super::{
    current_boot::CurrentStartup17,
    current_contracts::*,
    current_quotes::{CurrentControlQuote17, CurrentServiceQuote17},
    current_shared::{read_reference17, shared_row17},
};
use crate::{
    ProviderError,
    envelope::Envelope,
    protocol_snapshot::{
        PreparedArchivedNativeProtocolMapping,
        owned11::typed::{Fields, HistoricalType, Ledger, invalid, plain_string, unsigned},
    },
    reference_packet::{
        Native5Policy,
        control::PacketCompleteRestorePhysicalHold,
        service::{
            ack_emitter::{
                NativeAckBoot, PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof,
            },
            complete_restore::{transfer::*, *},
        },
    },
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordRows},
};
use crucible_node_format::{Bytes, ContentRef, Id, U64};
use serde_json::Value;
use std::{
    cell::RefCell,
    marker::PhantomData,
    mem::{align_of, size_of},
};

/// Pins one concrete field to the metadata rows consumed for that exact value.
pub(crate) struct BorrowedLineageField17<'body, 'rows, T> {
    raw: &'body [u8],
    rows: MetadataRecordRows<'rows>,
    end: usize,
    field_type: PhantomData<T>,
}

impl<'body, 'rows, T> BorrowedLineageField17<'body, 'rows, T> {
    pub(crate) fn raw_data(&self) -> &'body [u8] {
        self.raw
    }

    pub(crate) fn starting_rows_data(&self) -> MetadataRecordRows<'rows> {
        self.rows.clone()
    }

    pub(crate) fn ending_position_data(&self) -> usize {
        self.end
    }

    /// Checks that a selected concrete decoder consumed exactly this field's rows.
    ///
    /// # Errors
    /// Refuses an incomplete or over-consuming selected field decoder.
    pub(crate) fn authenticate_end_data(
        &self,
        ledger: &Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        if ledger.rows.encoded_position() != self.end {
            return Err(invalid());
        }
        Ok(())
    }
}

impl BorrowedLineageField17<'_, '_, Bytes> {
    /// Copies only the actual private birth key into its fixed inline DATA array.
    ///
    /// # Errors
    /// Refuses noncanonical base64url or any key whose decoded length is not32.
    pub(crate) fn key32_data(&self) -> Result<[u8; 32], ProviderError> {
        use base64::Engine;
        let mut key = [0; 32];
        let length = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_slice(plain_string(self.raw)?.as_bytes(), &mut key)
            .map_err(|_| invalid())?;
        if length != key.len() {
            return Err(invalid());
        }
        Ok(key)
    }
}

pub(crate) struct BorrowedBootDataLineage17<'body, 'rows> {
    pub(crate) private_key: BorrowedLineageField17<'body, 'rows, Bytes>,
    pub(crate) birth_id: BorrowedLineageField17<'body, 'rows, Bytes>,
    pub(crate) source_birth: BorrowedLineageField17<'body, 'rows, Value>,
    pub(crate) host_registration: BorrowedLineageField17<'body, 'rows, Value>,
    pub(crate) private_launch: BorrowedLineageField17<'body, 'rows, Id>,
    pub(crate) host_executable: BorrowedLineageField17<'body, 'rows, ContentRef>,
}

pub(crate) struct BorrowedCurrentPrepareLineage17<'body, 'rows> {
    definition: &'body [u8],
    group: usize,
    pub(crate) original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) request: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketCompleteRestorePrepareRequest>>,
    >,
    pub(crate) proof: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketCompleteRestoreTransferProof>>,
    >,
    pub(crate) context: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketCompleteRestorePrepareContext>>,
    >,
    pub(crate) receipt_body: BorrowedLineageField17<
        'body,
        'rows,
        crate::connection::settled17::HistoricalReversedByteBank17,
    >,
    custody_group: Option<usize>,
    pub(crate) verified: bool,
    pub(crate) receipt_started: bool,
    pub(crate) input_segment_issued: bool,
    pub(crate) input_segment_started: bool,
}

pub(crate) struct BorrowedCurrentCommitLineage17<'body, 'rows> {
    definition: &'body [u8],
    group: usize,
    mapping_group: usize,
    hold_group: Option<usize>,
    pub(crate) launch: Option<BorrowedControllerLineage17<'body, 'rows>>,
    pub(crate) original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) request: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketCompleteRestoreCommitRequest>>,
    >,
    pub(crate) proof: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketCompleteRestoreTransferProof>>,
    >,
    pub(crate) context: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketCompleteRestoreCommitContext>>,
    >,
    pub(crate) gate_data:
        BorrowedLineageField17<'body, 'rows, Option<CurrentDto17<PacketNativeRestoredCommitHold>>>,
    pub(crate) receipt_body: BorrowedLineageField17<
        'body,
        'rows,
        crate::connection::settled17::HistoricalReversedByteBank17,
    >,
    pub(crate) completed_response: BorrowedLineageField17<'body, 'rows, Option<ContentRef>>,
    pub(crate) verified: bool,
    pub(crate) installation_started: bool,
    pub(crate) receipt_started: bool,
}

/// Borrows complete lineage without reconstructing any old host-owner graph.
pub(crate) struct BorrowedCurrentBootLineage17<'body, 'rows> {
    definition: &'body [u8],
    group: usize,
    pub(crate) creator: u32,
    policy_group: usize,
    pub(crate) data: BorrowedBootDataLineage17<'body, 'rows>,
    pub(crate) launch:
        BorrowedLineageField17<'body, 'rows, crate::connection::settled17::HistoricalByteBank17>,
    pub(crate) normalized: [BorrowedLineageField17<'body, 'rows, Option<Value>>; 5],
    pub(crate) ack_context: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketCanonicalAckAdmissionContext>>,
    >,
    pub(crate) ack_proof: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketCanonicalAckAdmissionProof>>,
    >,
    pub(crate) ack_original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) commit: Option<BorrowedCurrentCommitLineage17<'body, 'rows>>,
    pub(crate) prepare: Option<BorrowedCurrentPrepareLineage17<'body, 'rows>>,
    pub(crate) stages: BorrowedStagesLineage17<'body, 'rows>,
    pub(crate) reserve: BorrowedReserveLineage17<'body, 'rows>,
    restored_suffix_maximum_originals: Option<U64>,
    pub(crate) ready: bool,
    pub(crate) attempted: bool,
    pub(crate) verified: bool,
}

fn role(raw: &[u8], literal: &str) -> Result<(), ProviderError> {
    if plain_string(raw)? != literal {
        return Err(invalid());
    }
    Ok(())
}

fn discard<T: HistoricalType>(
    raw: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    if ledger.read::<T>(raw, false)?.is_some() {
        return Err(invalid());
    }
    Ok(())
}

fn scalar<T: HistoricalType>(
    raw: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<T, ProviderError> {
    ledger.read::<T>(raw, true)?.ok_or_else(invalid)
}

pub(super) fn loan<'body, 'rows, T: HistoricalType>(
    raw: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedLineageField17<'body, 'rows, T>, ProviderError> {
    let rows = ledger.rows.clone();
    discard::<T>(raw, ledger)?;
    Ok(BorrowedLineageField17 {
        raw,
        rows,
        end: ledger.rows.encoded_position(),
        field_type: PhantomData,
    })
}

mod ancestry;
mod boot;
pub(crate) use ancestry::BorrowedRestorationAncestry17;
mod cache;
pub(crate) use cache::{CurrentNativeLineage17Data, CurrentNativeLineage17ReadAttempt};
mod commit;
mod controller;
pub(crate) use controller::BorrowedControllerLineage17;
mod mapping;
mod prepare;
pub(crate) use mapping::{
    BorrowedMappingLineage17, NativeMappingNormalization17,
    NativeMappingNormalization17ReadAttempt, read_shared_current_mapping_lineage17_data,
};

mod reserve;
mod stages;
pub(crate) use boot::read_shared_current_boot_lineage17_data;
pub(crate) use reserve::*;
pub(crate) use stages::*;

impl<'body> BorrowedCurrentBootLineage17<'body, '_> {
    /// Returns the selected sealed startup reservation's actual original limit.
    ///
    /// The enclosing graph authenticates this completed Boot before publishing
    /// this loan. No caller-supplied reservation participates in this getter.
    ///
    /// # Errors
    /// Refuses an unverified Boot or an absent sealed suffix startup reservation.
    pub(crate) fn restored_suffix_maximum_originals_data(&self) -> Result<U64, ProviderError> {
        if !self.ready || !self.verified {
            return Err(invalid());
        }
        self.restored_suffix_maximum_originals.ok_or_else(invalid)
    }

    pub(crate) fn group_data(&self) -> usize {
        self.group
    }

    pub(crate) fn policy_group_data(&self) -> usize {
        self.policy_group
    }

    pub(crate) fn definition_data(&self) -> &'body [u8] {
        self.definition
    }
}

impl<'body> BorrowedCurrentPrepareLineage17<'body, '_> {
    pub(crate) fn group_data(&self) -> usize {
        self.group
    }

    pub(crate) fn custody_group_data(&self) -> Option<usize> {
        self.custody_group
    }

    pub(crate) fn definition_data(&self) -> &'body [u8] {
        self.definition
    }
}

impl<'body> BorrowedCurrentCommitLineage17<'body, '_> {
    pub(crate) fn group_data(&self) -> usize {
        self.group
    }

    pub(crate) fn mapping_group_data(&self) -> usize {
        self.mapping_group
    }

    pub(crate) fn hold_group_data(&self) -> Option<usize> {
        self.hold_group
    }

    pub(crate) fn definition_data(&self) -> &'body [u8] {
        self.definition
    }
}
