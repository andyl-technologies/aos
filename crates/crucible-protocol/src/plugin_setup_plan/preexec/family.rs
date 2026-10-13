//! Checks fixed reservation syntax without constructing a containing issuer.
//!
//! ```text
//! family[256] = CRUCFAM1 | BE schema1/length256 | cap32 | account | assignment
//! row[96] = role u32 | zero u32 | identity32 | extent | zero u64
//!           memory | FSIZE | tasks | NOFILE | vCPUs
//! ```
//!
//! Both rows describe immutable reservations. Their reserved execution field
//! stays zero; Source execution remains in the separate local Purpose record.

use super::{PluginSetupPlanError, read_u32, read_u64};

pub(super) fn validate(purpose: &[u8]) -> Result<(), PluginSetupPlanError> {
    let invalid = || PluginSetupPlanError::InvalidPreexecSection {
        section: "fixed family reservations",
    };
    let family = purpose.get(744..1000).ok_or_else(invalid)?;
    if family[..8] != *b"CRUCFAM1"
        || read_u32(family, 8)? != 1
        || read_u32(family, 12)? != 256
        || family[16..48] == [0; 32]
        || family[16..48] != purpose[184..216]
        || read_u64(family, 48)? == 0
        || family[48..56] != purpose[88..96]
        || read_u64(family, 56)? == 0
        || read_u64(purpose, 488)? != 0
        || read_u64(purpose, 480)? != 2
    {
        return Err(invalid());
    }

    let parent_tasks = read_u64(purpose, 544)?;
    let parent_quota = read_u64(purpose, 528)?;
    let mut assigned = 0_u64;
    for index in 0..2 {
        let row = &family[64 + index * 96..160 + index * 96];
        let extent = read_u64(row, 40)?;
        let memory = read_u64(row, 56)?;
        if read_u32(row, 0)? != index as u32
            || row[4..8] != [0; 4]
            || row[8..40] == [0; 32]
            || extent == 0
            || read_u64(row, 48)? != 0
            || memory == 0
            || memory > extent
            || memory == u64::MAX
            || read_u64(row, 64)? == u64::MAX
        {
            return Err(invalid());
        }
        for offset in [72, 80, 88] {
            if matches!(read_u64(row, offset)?, 0 | u64::MAX) {
                return Err(invalid());
            }
        }
        // These are per-process ceilings under the one retained aggregate.
        // Checking each against the parent does not add another task/CPU bank.
        if read_u64(row, 72)? > parent_tasks
            || read_u64(row, 88)?
                .checked_mul(100_000)
                .is_none_or(|quota| quota > parent_quota)
        {
            return Err(invalid());
        }
        assigned = assigned.checked_add(extent).ok_or_else(invalid)?;
    }
    if family[72..104] == family[168..200] || assigned > read_u64(purpose, 24)? {
        return Err(invalid());
    }
    let source = &family[64..160];
    for (row_offset, purpose_offset) in [
        (40, 472),
        (56, 104),
        (64, 112),
        (72, 120),
        (80, 128),
        (88, 136),
    ] {
        if source[row_offset..row_offset + 8] != purpose[purpose_offset..purpose_offset + 8] {
            return Err(invalid());
        }
    }
    Ok(())
}
