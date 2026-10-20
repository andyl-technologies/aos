//! Commits the whole independently captured Controller map and global native cut.
//!
//! ```text
//! protected-directory/journal/lock-names:48 | global-NEXT:u64be |
//! native-end:u64be | complete-materialized-state-head:32
//! ```
//!
//! This is comparison DATA, not a native COMMIT hash or live barrier. The actual
//! Controller keeps its writer/mutex and opaque same-instance snapshot through
//! every crossing. Any intervening append invalidates that global epoch even
//! when the selected six rows remain equal.

use super::super::protected_names::ProtectedJournalNamesV1;
use super::{RootExecutionNoApplyFloorDataErrorV2 as Error, field};
use aos_sandbox_model::RecordNamespace;
use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8] = b"aos.sandbox.root.execution-no-apply-controller-global-cut.v2\0";
/// Names the fixed comparison width of one final global Controller cut.
pub const ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2: usize = 96;

/// Retains exact global C coordinates without minting a current Controller owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExecutionNoApplyControllerCutDataV2 {
    names: ProtectedJournalNamesV1,
    next: u64,
    end: u64,
    state_head: [u8; 32],
}

impl RootExecutionNoApplyControllerCutDataV2 {
    /// Hashes the whole ordered canonical map and actual native-cut coordinates.
    ///
    /// # Errors
    /// Rejects zero native names/positions, arithmetic overflow or nonincreasing
    /// namespace/key order. Caller bytes are never accepted as native custody.
    pub fn from_rows_data_v2<'rows>(
        names: ProtectedJournalNamesV1,
        next: u64,
        end: u64,
        rows: impl IntoIterator<Item = (RecordNamespace, &'rows [u8], &'rows [u8])>,
    ) -> Result<Self, Error> {
        ProtectedJournalNamesV1::from_bytes(&names.to_bytes()).map_err(|_| Error)?;
        if next == 0 || end == 0 {
            return Err(Error);
        }
        let mut hash = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(names.to_bytes())
            .chain_update(next.to_be_bytes())
            .chain_update(end.to_be_bytes());
        let mut previous = None;
        let mut count = 0_u64;
        for (namespace, key, value) in rows {
            if previous.is_some_and(|prior| prior >= (namespace, key)) {
                return Err(Error);
            }
            hash.update([namespace as u8]);
            hash.update(u64::try_from(key.len()).map_err(|_| Error)?.to_be_bytes());
            hash.update(key);
            hash.update(u64::try_from(value.len()).map_err(|_| Error)?.to_be_bytes());
            hash.update(value);
            count = count.checked_add(1).ok_or(Error)?;
            previous = Some((namespace, key));
        }
        hash.update(count.to_be_bytes());
        Ok(Self {
            names,
            next,
            end,
            state_head: hash.finalize().into(),
        })
    }

    /// Encodes only the inert fixed native coordinates and complete map head.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2] {
        let mut bytes = [0; ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2];
        bytes[..48].copy_from_slice(&self.names.to_bytes());
        bytes[48..56].copy_from_slice(&self.next.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.end.to_be_bytes());
        bytes[64..].copy_from_slice(&self.state_head);
        bytes
    }

    /// Decodes structural cut DATA; the actual native owner must recompute it.
    ///
    /// # Errors
    /// Rejects another width, zero native names, zero positions or empty head.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ROOT_EXECUTION_NO_APPLY_CONTROLLER_CUT_BYTES_V2 {
            return Err(Error);
        }
        let names = ProtectedJournalNamesV1::from_bytes(&bytes[..48]).map_err(|_| Error)?;
        let next = u64::from_be_bytes(field(bytes, 48)?);
        let end = u64::from_be_bytes(field(bytes, 56)?);
        let state_head = field(bytes, 64)?;
        if next == 0 || end == 0 || state_head == [0; 32] {
            return Err(Error);
        }
        Ok(Self {
            names,
            next,
            end,
            state_head,
        })
    }

    /// Returns the protected directory/journal/lock comparison names.
    #[must_use]
    pub const fn names(self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the global native epoch that every append advances.
    #[must_use]
    pub const fn next(self) -> u64 {
        self.next
    }

    /// Returns the exact captured native durable-end coordinate.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Returns the complete materialized-state commitment, not a COMMIT hash.
    #[must_use]
    pub const fn state_head(self) -> [u8; 32] {
        self.state_head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_rows_and_same_map_new_native_epoch_change_the_global_cut() {
        let names = ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4));
        let selected = (
            RecordNamespace::Operation,
            b"create".as_slice(),
            b"applying".as_slice(),
        );
        let old =
            RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(names, 10, 1000, [selected])
                .unwrap();
        let extra = RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
            names,
            10,
            1000,
            [
                (
                    RecordNamespace::DesiredState,
                    b"other".as_slice(),
                    b"changed".as_slice(),
                ),
                selected,
            ],
        )
        .unwrap();
        let new_epoch =
            RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(names, 11, 1100, [selected])
                .unwrap();
        assert_ne!(old, extra);
        assert_ne!(old, new_epoch);
        assert_eq!(
            RootExecutionNoApplyControllerCutDataV2::decode_canonical(&old.encode_canonical())
                .unwrap(),
            old
        );
        assert!(
            RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
                names,
                10,
                1000,
                [selected, selected]
            )
            .is_err()
        );
    }
}
