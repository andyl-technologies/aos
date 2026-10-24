//! Bounds actual publisher pages and shared-object namespace enumeration.

use super::{
    NativeRecoveryInspector,
    files::{directory_flags, invalid},
};
use crate::publisher_local::{
    Error as PublisherError,
    wire::{BodyKey, BodyKind},
};
use rustix::fs::{Dir, Mode, openat};
use std::{collections::BTreeMap, fs::File, io};

type KeyOrder = (i32, Vec<u8>, u32, Vec<u8>);

pub(super) struct Candidates {
    keys: BTreeMap<KeyOrder, BodyKey>,
    remaining: usize,
    pub(super) publisher_entries: usize,
    pub(super) namespace_entries: usize,
    pub(super) duplicates: usize,
    pub(super) inventory_failure: Option<PublisherError>,
    pub(super) namespace_failure: Option<io::Error>,
}

impl Candidates {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            keys: BTreeMap::new(),
            remaining: limit,
            publisher_entries: 0,
            namespace_entries: 0,
            duplicates: 0,
            inventory_failure: None,
            namespace_failure: None,
        }
    }

    fn charge(&mut self) -> io::Result<()> {
        self.remaining = self.remaining.checked_sub(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "recovery candidate budget exceeded",
            )
        })?;
        Ok(())
    }

    fn insert(&mut self, key: BodyKey) {
        let order = (
            key.kind,
            key.descriptor.clone(),
            key.codec,
            key.pack_id.clone(),
        );
        if self.keys.insert(order, key).is_some() {
            self.duplicates += 1;
        }
    }

    fn publisher_key(&mut self, key: BodyKey) -> io::Result<()> {
        // Charge occurrences before deduplication. Repeated pages can never
        // evade the bound by repeating one registered key.
        self.charge()?;
        self.publisher_entries += 1;
        self.insert(key);
        Ok(())
    }

    pub(super) fn publisher(&mut self, context: &NativeRecoveryInspector) -> io::Result<()> {
        let mut cursor = None;
        loop {
            context.check_current()?;
            let page = match context.session.inventory(cursor.take()) {
                Ok(page) => page,
                Err(error) => {
                    // A lost reply can leave publisher-owned work or custody.
                    // Retain uncertainty while independently inspecting shared
                    // files; this report cannot authorize completion or Resume.
                    self.inventory_failure = Some(error);
                    return Ok(());
                }
            };
            if page.keys.len() > 64 || (page.keys.is_empty() && page.next_cursor.is_some()) {
                return Err(invalid(
                    "publisher inventory page is oversized or makes no progress",
                ));
            }
            for key in page.keys {
                self.publisher_key(key)?;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(());
            }
        }
    }

    pub(super) fn shared_packs(&mut self, context: &NativeRecoveryInspector) -> io::Result<()> {
        let objects = context
            .layout
            .directories
            .get("objects")
            .ok_or_else(|| invalid("missing retained objects directory"))?;
        let packs = match openat(objects, "pack", directory_flags(), Mode::empty()) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let shards = self.names(&packs)?;
        for shard in shards {
            decode_hex(&shard, 1)?;
            let directory = File::from(openat(&packs, &shard, directory_flags(), Mode::empty())?);
            for name in self.names(&directory)? {
                let (id, extension) = name
                    .split_once('.')
                    .ok_or_else(|| invalid("noncanonical shared pack candidate name"))?;
                if !matches!(extension, "pack" | "idx") || !id.starts_with(&shard) {
                    return Err(invalid(
                        "noncanonical shared pack candidate shard or extension",
                    ));
                }
                self.insert(BodyKey {
                    kind: BodyKind::Pack as i32,
                    descriptor: Vec::new(),
                    codec: 0,
                    pack_id: decode_hex(id, 16)?,
                });
            }
        }
        context.check_current()
    }

    fn names(&mut self, directory: &File) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in Dir::read_from(directory)? {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            self.charge()?;
            self.namespace_entries += 1;
            names.push(std::str::from_utf8(bytes).map_err(invalid)?.to_owned());
        }
        names.sort();
        Ok(names)
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = &BodyKey> {
        self.keys.values()
    }
}

fn decode_hex(name: &str, width: usize) -> io::Result<Vec<u8>> {
    if name.len() != width * 2
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("noncanonical shared-content hexadecimal name"));
    }
    let (pairs, _) = name.as_bytes().as_chunks::<2>();
    Ok(pairs
        .iter()
        .map(|pair| {
            let nibble = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_candidates_consume_the_occurrence_budget() {
        let mut candidates = Candidates::new(2);
        let key = BodyKey {
            kind: BodyKind::Pack as i32,
            pack_id: vec![1; 16],
            ..Default::default()
        };
        for _ in 0..2 {
            candidates.publisher_key(key.clone()).unwrap();
        }
        assert_eq!(candidates.keys().count(), 1);
        assert_eq!(candidates.duplicates, 1);
        assert_eq!(candidates.publisher_entries, 2);
        assert_eq!(
            candidates.publisher_key(key).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
    }

    #[test]
    fn native_names_reject_aliases_and_wrong_widths() {
        assert_eq!(decode_hex("00ff", 2).unwrap(), [0, 255]);
        for name in ["00FF", "../a", "000", "gggg", "0xff"] {
            assert!(decode_hex(name, 2).is_err());
        }
    }
}
