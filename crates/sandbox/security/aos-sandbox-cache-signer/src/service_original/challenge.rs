//! Checks the fixed request through the existing Hello and Held codecs.
//!
//! These copied fields are comparison DATA. The enclosing private service must
//! independently join the actual Root profile/PID1 and Controller task, read
//! all five native views, and retain every owed post before signing a reply.

use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RECORD_HEADER_BYTES, RecordEnvelopeV1,
    cache_held::{CacheHeldBodyDataV1, CacheHeldReceiptDataV1, CacheJournalDataV1},
    root_open::{
        ROOT_HELLO_FRAME_BYTES_V1, ROOT_OPEN_BODY_BYTES_V1, RootHelloDataV1, RootOpenBodyDataV1,
    },
    transport::FRAME_HEADER_BYTES,
};

use super::CacheSignerReceivingClosedV1 as Closed;
use super::request::CacheCurrentRequestOriginalV1;

#[derive(Clone, Copy)]
pub(super) struct CacheCurrentChallengeDataV1 {
    pub(super) root: RootOpenBodyDataV1,
    pub(super) root_checksum: [u8; 32],
    pub(super) held: CacheHeldBodyDataV1,
    /// Expected current coordinates; the actual five-view replay must match them.
    pub(super) expected_current: CacheHeldBodyDataV1,
    pub(super) held_checksum: [u8; 32],
    pub(super) cutoff: u64,
}

#[derive(Default)]
pub(super) struct CacheCurrentChallengeOriginalV1 {
    root: Option<Result<RootOpenBodyDataV1, HistoryErrorV1>>,
    hello: Option<Result<(RootOpenBodyDataV1, [u8; 32]), HistoryErrorV1>>,
    receipt: Option<Result<(), HistoryErrorV1>>,
    held: Option<Result<CacheHeldBodyDataV1, HistoryErrorV1>>,
    joined: Option<Result<CacheCurrentChallengeDataV1, HistoryErrorV1>>,
}

impl CacheCurrentChallengeOriginalV1 {
    pub(super) fn decode_once(
        &mut self,
        request: &CacheCurrentRequestOriginalV1,
    ) -> Result<(), Closed> {
        if self.root.is_some() {
            return Err(Closed);
        }
        let bytes = request.bytes()?;
        let hello = &bytes[8..8 + ROOT_HELLO_FRAME_BYTES_V1];
        // Only the existing body decoder derives the untrusted correlation.
        // The SAME complete Hello decoder then checks record/frame checksums,
        // initial phases, coordinates and the extracted Open in their entirety.
        let offset = FRAME_HEADER_BYTES + RECORD_HEADER_BYTES;
        self.root = Some(RootOpenBodyDataV1::decode(
            &hello[offset..offset + ROOT_OPEN_BODY_BYTES_V1],
        ));
        let root = *positive(&self.root)?;
        self.hello = Some(
            RootHelloDataV1::decode(hello, root.open).map(|value| (value.body, value.checksum)),
        );
        let (root, checksum) = *positive(&self.hello)?;
        let receipt = match CacheHeldReceiptDataV1::decode(
            &bytes[8 + ROOT_HELLO_FRAME_BYTES_V1..],
            root.open.lane,
        ) {
            Ok(receipt) => {
                self.receipt = Some(Ok(()));
                receipt
            }
            Err(error) => {
                self.receipt = Some(Err(error));
                return Err(Closed);
            }
        };
        self.held = Some(receipt.body(root.open.lane));
        let held = *positive(&self.held)?;
        self.joined = Some((|| {
            if root.open.seed != held.association.seed
                || root.open.controller_nonce != held.association.controller_nonce
                || root.boot != held.association.boot
            {
                return Err(HistoryErrorV1::Correlation);
            }
            let record = RecordEnvelopeV1::decode(
                receipt.record,
                KeyV1::new(root.open.lane, OwnerV1::Cache, 1)?,
                PhaseV1::new(OwnerV1::Cache, 1)?,
            )?;
            let mut expected_current = held;
            expected_current.hold = CacheJournalDataV1 {
                names: receipt.hold_names,
                next: receipt.hold_after_next,
                end: receipt.hold_after_end,
            };
            Ok(CacheCurrentChallengeDataV1 {
                root,
                root_checksum: checksum,
                held,
                expected_current,
                held_checksum: record.checksum(),
                cutoff: root.cutoff.min(held.association.cutoff),
            })
        })());
        positive(&self.joined).map(|_| ())
    }

    pub(super) fn data(&self) -> Result<&CacheCurrentChallengeDataV1, Closed> {
        positive(&self.joined)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        super::cause(&self.root)
            .or_else(|| super::cause(&self.hello))
            .or_else(|| super::cause(&self.receipt))
            .or_else(|| super::cause(&self.held))
            .or_else(|| super::cause(&self.joined))
    }
}

fn positive<T>(slot: &Option<Result<T, HistoryErrorV1>>) -> Result<&T, Closed> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(Closed)
}
