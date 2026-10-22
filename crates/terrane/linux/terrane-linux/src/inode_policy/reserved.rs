//! Reserves fixed open-addressed inode storage before a connection starts.
//!
//! Slots never move, grow or become vacant after first touch. At most half the
//! slots can be occupied, so every probe terminates at a retained row or vacancy.

use super::{Error, FIRST_INODE, Inode, NodeIdentity};

#[derive(Clone, Copy)]
struct Row {
    identity: NodeIdentity,
    inode: Inode,
}

pub(super) struct Slots {
    rows: Vec<Option<Row>>,
    len: u32,
}

impl Slots {
    pub(super) fn new(limit: u32, max_bytes: usize) -> Result<Self, Error> {
        let slots = usize::try_from(limit)
            .ok()
            .and_then(|limit| limit.checked_mul(2))
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::MemoryBudget)?;
        let bytes = slots
            .checked_mul(std::mem::size_of::<Option<Row>>())
            .filter(|bytes| *bytes <= isize::MAX as usize && *bytes <= max_bytes)
            .ok_or(Error::MemoryBudget)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(slots)
            .map_err(|_| Error::Allocation)?;
        rows.resize_with(slots, || None);
        debug_assert_eq!(rows.len() * std::mem::size_of::<Option<Row>>(), bytes);

        Ok(Self { rows, len: 0 })
    }

    pub(super) fn touch(
        &mut self,
        identity: NodeIdentity,
        links: u32,
        limit: u32,
    ) -> Result<Inode, Error> {
        let mask = self.rows.len() - 1;
        // All identity bits are already derived from BLAKE3. Truncation here
        // chooses a probe start; it never substitutes for the full comparison.
        let mut slot = (identity.node_id as usize) & mask;
        for _ in 0..self.rows.len() {
            match self.rows[slot] {
                Some(row) if row.identity.node_id == identity.node_id => {
                    if row.identity.digest != identity.digest {
                        return Err(Error::Collision);
                    }
                    if row.inode.links != links {
                        return Err(Error::Links);
                    }
                    return Ok(row.inode);
                }
                Some(_) => slot = (slot + 1) & mask,
                None => {
                    if self.len >= limit {
                        return Err(Error::Capacity);
                    }
                    let inode = Inode {
                        number: FIRST_INODE.checked_add(self.len).ok_or(Error::Capacity)?,
                        links,
                    };
                    self.rows[slot] = Some(Row { identity, inode });
                    self.len += 1;
                    return Ok(inode);
                }
            }
        }

        Err(Error::Capacity)
    }

    pub(super) fn len(&self) -> usize {
        self.len as usize
    }
}
