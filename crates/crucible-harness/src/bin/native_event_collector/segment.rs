//! Strict decoder for canonical scheduler event-log segments.

const MAGIC: &[u8; 16] = b"CRUCIBLE-ELOGSEG";
const VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) sequence: u64,
    pub(super) virtual_ticks: u64,
    pub(super) icount_retired: u64,
    pub(super) kind: String,
    pub(super) material: String,
}

pub(super) fn has_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub(super) fn decode(bytes: &[u8], maximum_entries: u64) -> Result<Vec<Entry>, String> {
    let mut cursor = Cursor::new(bytes);
    if cursor.read_exact("magic", MAGIC.len())? != MAGIC {
        return Err(String::from("invalid event-segment magic"));
    }
    let version = cursor.read_u32("version")?;
    if version != VERSION {
        return Err(format!("unsupported event-segment version {version}"));
    }
    cursor.read_exact("previous prefix", 32)?;
    let entry_count = cursor.read_u64("entry count")?;
    if entry_count > maximum_entries {
        return Err(format!(
            "event segment declares {entry_count} entries above bound {maximum_entries}"
        ));
    }
    let capacity = usize::try_from(entry_count)
        .map_err(|_| format!("event entry count {entry_count} is not representable"))?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(capacity)
        .map_err(|_| format!("reserve {entry_count} decoded event entries"))?;
    for _ in 0..entry_count {
        let sequence = cursor.read_u64("entry sequence")?;
        let virtual_ticks = cursor.read_u64("entry virtual time")?;
        let icount_retired = cursor.read_u64("entry icount")?;
        match cursor.read_u8("entry node presence")? {
            0 => {}
            1 => {
                cursor.read_string("entry node")?;
            }
            value => return Err(format!("invalid event entry node-presence flag {value}")),
        }
        cursor.read_string("entry source")?;
        let level = cursor.read_u8("entry level")?;
        if level > 4 {
            return Err(format!("invalid event entry level {level}"));
        }
        let class = cursor.read_u8("entry class")?;
        if class > 1 {
            return Err(format!("invalid event entry class {class}"));
        }
        let kind = cursor.read_string("entry payload kind")?;
        cursor.read_u64("entry payload attribute count")?;
        let content_hash = cursor.read_exact("entry content hash", 32)?;
        let material = cursor.read_string("entry material")?;
        if content_hash != entry_content_hash(material.as_bytes()) {
            return Err(format!(
                "event entry {sequence} content hash does not authenticate its material"
            ));
        }
        entries.push(Entry {
            sequence,
            virtual_ticks,
            icount_retired,
            kind,
            material,
        });
    }
    cursor.finish()?;
    Ok(entries)
}

pub(super) fn entry_content_hash(material: &[u8]) -> [u8; 32] {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.content-hash.v1");
    hasher.write_bytes(b"crucible.scheduler.event-log.entry.v1");
    hasher.write_bytes(material);
    hasher.finish()
}

struct MaterialHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

impl MaterialHasher {
    fn new() -> Self {
        Self {
            lanes: [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ],
            bytes_written: 0,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u64(bytes.len() as u64);
        let (chunks, remainder) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.mix_word(u64::from_le_bytes(*chunk));
        }
        if !remainder.is_empty() {
            let mut word = [0; 8];
            word[..remainder.len()].copy_from_slice(remainder);
            self.mix_word(u64::from_le_bytes(word));
        }
        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
    }

    fn write_u64(&mut self, value: u64) {
        self.mix_word(value);
        self.bytes_written = self.bytes_written.wrapping_add(8);
    }

    fn mix_word(&mut self, word: u64) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            let rotation = 13 + (index as u32 * 7);
            let salt = (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            *lane ^= word.wrapping_add(salt);
            *lane = lane
                .rotate_left(rotation)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane ^= *lane >> 33;
        }
    }

    fn finish(&self) -> [u8; 32] {
        let mut lanes = self.lanes;
        for (index, lane) in lanes.iter_mut().enumerate() {
            let salt = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            *lane = finalize_hash_word(lane.wrapping_add(self.bytes_written).wrapping_add(salt));
        }
        let mut bytes = [0; 32];
        for (index, lane) in lanes.iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&lane.to_le_bytes());
        }
        bytes
    }
}

fn finalize_hash_word(mut word: u64) -> u64 {
    word ^= word >> 30;
    word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    word ^= word >> 27;
    word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
    word ^ (word >> 31)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, field: &str, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| format!("{field} offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| format!("truncated {field}"))?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self, field: &str) -> Result<u8, String> {
        Ok(self.read_exact(field, 1)?[0])
    }

    fn read_u32(&mut self, field: &str) -> Result<u32, String> {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.read_exact(field, 4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self, field: &str) -> Result<u64, String> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.read_exact(field, 8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_string(&mut self, field: &str) -> Result<String, String> {
        let length = self.read_u64(field)?;
        let length = usize::try_from(length)
            .map_err(|_| format!("{field} length {length} is not representable"))?;
        let bytes = self.read_exact(field, length)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| format!("{field} is not UTF-8"))
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(format!(
                "event segment has {} trailing bytes",
                self.bytes.len() - self.offset
            ))
        }
    }
}
