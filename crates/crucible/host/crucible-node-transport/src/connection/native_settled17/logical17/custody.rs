//! Mirrors the defining resolved-custody cut on borrowed receiver/pin evidence.

use super::{BorrowedAuthority17Lineage, bytes::*};
use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Fields, invalid, plain_string};

/// Keeps nonrefunded debit and identity populations without copying blob banks.
#[derive(Clone, Copy)]
pub(crate) struct BorrowedBlobCustody17<'a> {
    pub(crate) receiver: &'a [u8],
    pub(crate) ledger: &'a [u8],
    pub(crate) records: &'a [u8],
    pub(crate) reserved: usize,
    pub(crate) next_pin: u64,
    pub(crate) pins_created: usize,
}

pub(crate) fn authenticate_borrowed_settled_capture17_custody_data<'a>(
    receiver: &'a [u8],
    wrappers: &[u8],
    authority: BorrowedAuthority17Lineage<'_>,
) -> Result<BorrowedBlobCustody17<'a>, ProviderError> {
    let session = item(receiver, 1)?;
    let incarnation = item(receiver, 2)?;
    if session != authority.session || incarnation != authority.incarnation {
        return Err(invalid());
    }
    let limits = item(receiver, 3)?;
    let maximum_reserved = quantity(item(limits, 0)?)?;
    let maximum_content = quantity(item(limits, 1)?)?;
    let maximum_chunk = quantity(item(limits, 2)?)?;
    let maximum_active = quantity(item(limits, 3)?)?;
    let maximum_retired = quantity(item(limits, 4)?)?;
    let maximum_chunks = quantity(item(limits, 5)?)?;
    let maximum_pins = quantity(item(limits, 6)?)?;
    let ledger = item(receiver, 4)?;
    let reserved = quantity(item(ledger, 1)?)?;
    let next_pin = quoted(item(ledger, 2)?)?;
    let pins_created = quantity(item(ledger, 3)?)?;
    let records = item(ledger, 4)?;
    let mut cursor = Fields::array(records)?;
    let mut actual_reserved = 0usize;
    let mut actual_pins = 0usize;
    let mut pin_ids = [0u64; 2048];
    let mut active = [0usize; 2];
    let mut retired = [0usize; 2];
    while let Some(record) = cursor.next()? {
        let key = item(record, 0)?;
        if item(key, 1)? != session || item(key, 2)? != incarnation {
            return Err(invalid());
        }
        let origin = match plain_string(item(key, 0)?)? {
            "controller" => 0,
            "provider" => 1,
            _ => return Err(invalid()),
        };
        let content = item(record, 1)?;
        let length = quantity(item(record, 2)?)?;
        let (bytes, _) = Bytes17::bank(item(record, 3)?, false)?;
        let chunks = item(record, 4)?;
        let verified = boolean(item(record, 5)?)?;
        let quarantined = boolean(item(record, 6)?)?;
        let exposed = boolean(item(record, 7)?)?;
        let retirement = item(record, 8)?;
        let pins = item(record, 9)?;
        let charged = boolean(item(record, 10)?)?;
        if quoted(field(content, "length")?)? != u64::try_from(length).map_err(|_| invalid())?
            || length > maximum_content
            || bytes.len() > length
            || count(chunks)? > maximum_chunks
        {
            return Err(invalid());
        }
        let pin_count = count(pins)?;
        if exposed && pin_count == 0 || pin_count != 0 && (!exposed || !verified) {
            return Err(invalid());
        }
        let mut pin_cursor = Fields::array(pins)?;
        while let Some(pin) = pin_cursor.next()? {
            let id = quoted(item(pin, 0)?)?;
            if id == 0
                || id >= next_pin
                || id > 131072
                || plain_string(item(pin, 3)?)? != "settled"
                || item(pin, 4)? == b"null"
            {
                return Err(invalid());
            }
            let index = usize::try_from(id - 1).map_err(|_| invalid())?;
            let word = pin_ids.get_mut(index / 64).ok_or_else(invalid)?;
            let bit = 1u64 << (index % 64);
            if *word & bit != 0 {
                return Err(invalid());
            }
            *word |= bit;
            actual_pins = actual_pins.checked_add(1).ok_or_else(invalid)?;
        }
        pin_cursor.finish()?;
        let is_retired = plain_string(item(retirement, 0)?)? != "none";
        if is_retired {
            if charged || bytes.len() != 0 || count(chunks)? != 0 {
                return Err(invalid());
            }
            retired[origin] = retired[origin].checked_add(1).ok_or_else(invalid)?;
        } else {
            if quarantined || !verified || !charged || bytes.len() != length {
                return Err(invalid());
            }
            active[origin] = active[origin].checked_add(1).ok_or_else(invalid)?;
            authenticate_content(content, bytes)?;
            let mut boundaries = Fields::array(chunks)?;
            let mut end = 0usize;
            while let Some(chunk) = boundaries.next()? {
                let offset = quantity(item(chunk, 0)?)?;
                let extent = quantity(item(chunk, 1)?)?;
                if offset != end || extent == 0 || extent > maximum_chunk {
                    return Err(invalid());
                }
                end = end
                    .checked_add(extent)
                    .filter(|end| *end <= length)
                    .ok_or_else(invalid)?;
            }
            boundaries.finish()?;
            if end != length {
                return Err(invalid());
            }
            actual_reserved = actual_reserved.checked_add(length).ok_or_else(invalid)?;
        }
    }
    cursor.finish()?;
    if actual_reserved != reserved
        || reserved > maximum_reserved
        || actual_pins != pins_created
        || pins_created > maximum_pins
        || u64::try_from(pins_created)
            .map_err(|_| invalid())?
            .checked_add(1)
            != Some(next_pin)
        || active.into_iter().any(|count| count > maximum_active)
        || retired.into_iter().any(|count| count > maximum_retired)
    {
        return Err(invalid());
    }
    let mut cursor = Fields::array(wrappers)?;
    while let Some(wrapper) = cursor.next()? {
        if !boolean(field(wrapper, "settled")?)? {
            return Err(invalid());
        }
        let key = field(wrapper, "key")?;
        let id = quoted(field(wrapper, "pin")?)?;
        let mut entries = Fields::array(records)?;
        let mut found = None;
        while let Some(record) = entries.next()? {
            if item(record, 0)? == key {
                found = Some(record);
                break;
            }
        }
        let record = found.ok_or_else(invalid)?;
        let mut pins = Fields::array(item(record, 9)?)?;
        let mut found = None;
        while let Some(pin) = pins.next()? {
            if quoted(item(pin, 0)?)? == id {
                found = Some(pin);
                break;
            }
        }
        let pin = found.ok_or_else(invalid)?;
        if item(pin, 1)? != field(wrapper, "owner")?
            || item(pin, 2)? != field(wrapper, "schema")?
            || plain_string(item(pin, 3)?)? != "settled"
            || item(pin, 4)? == b"null"
        {
            return Err(invalid());
        }
    }
    cursor.finish()?;
    Ok(BorrowedBlobCustody17 {
        receiver,
        ledger,
        records,
        reserved,
        next_pin,
        pins_created,
    })
}
