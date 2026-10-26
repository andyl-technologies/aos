//! Retains a bounded native enumeration of the fixed credential directory.

use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsFd as _;

use super::{NAMES, REQUIRED_CREDENTIAL_SLOTS};

struct Entry {
    name: [u8; 64],
    length: usize,
    inode: u64,
    kind: rustix::fs::FileType,
}

pub(super) struct Entries {
    buffer: [MaybeUninit<u8>; 4096],
    entries: [Option<rustix::io::Result<Entry>>; NAMES.len() + 3],
    eof: bool,
    entered: bool,
}

impl Entries {
    pub(super) fn new() -> Self {
        Self {
            buffer: [MaybeUninit::uninit(); 4096],
            entries: std::array::from_fn(|_| None),
            eof: false,
            entered: false,
        }
    }

    pub(super) fn observe(&mut self, file: &File, selected: &[bool; NAMES.len()]) -> bool {
        if self.entered {
            return false;
        }
        self.entered = true;
        if selected[8] != selected[9]
            || selected[8] != selected[15]
            || selected[8] != selected[16]
            || selected[20..24].iter().any(|value| *value != selected[8])
            || selected[27] != selected[28]
            || !REQUIRED_CREDENTIAL_SLOTS
                .iter()
                .all(|index| selected[*index])
        {
            return false;
        }
        let mut directory = rustix::fs::RawDir::new(file.as_fd(), &mut self.buffer);
        let mut seen = [false; NAMES.len() + 2];
        for slot in &mut self.entries {
            match directory.next() {
                None => {
                    self.eof = true;
                    return seen[..2].iter().all(|seen| *seen) && seen[2..] == selected[..];
                }
                Some(Err(error)) => {
                    *slot = Some(Err(error));
                    return false;
                }
                Some(Ok(entry)) => {
                    let bytes = entry.file_name().to_bytes();
                    let mut name = [0; 64];
                    let copied = bytes.len().min(name.len());
                    name[..copied].copy_from_slice(&bytes[..copied]);
                    *slot = Some(Ok(Entry {
                        name,
                        length: bytes.len(),
                        inode: entry.ino(),
                        kind: entry.file_type(),
                    }));
                    let index = match bytes {
                        b"." => Some(0),
                        b".." => Some(1),
                        name => NAMES
                            .iter()
                            .position(|expected| expected.as_bytes() == name)
                            .map(|n| n + 2),
                    };
                    let Some(index) = index else {
                        return false;
                    };
                    if seen[index] || (index >= 2 && !selected[index - 2]) {
                        return false;
                    }
                    seen[index] = true;
                }
            }
        }
        false
    }

    #[cfg(test)]
    fn retained_names(&self) -> Vec<&[u8]> {
        self.entries
            .iter()
            .filter_map(|entry| {
                let entry = entry.as_ref()?.as_ref().ok()?;
                let _ = (entry.inode, entry.kind);
                entry.name.get(..entry.length)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_directory_requires_the_complete_fixed_public_and_private_roster() {
        let directory = tempfile::tempdir().unwrap();
        for name in NAMES {
            std::fs::write(directory.path().join(name), b"data").unwrap();
        }
        let file = File::open(directory.path()).unwrap();
        let mut complete = Entries::new();

        assert!(complete.observe(&file, &[true; NAMES.len()]));
        assert!(complete.eof);
        for name in NAMES {
            assert!(complete.retained_names().contains(&name.as_bytes()));
        }

        std::fs::remove_file(directory.path().join(NAMES[3])).unwrap();
        let file = File::open(directory.path()).unwrap();
        let mut missing = Entries::new();

        assert!(!missing.observe(&file, &[true; NAMES.len()]));
        assert!(missing.eof);
        assert!(!missing.retained_names().contains(&NAMES[3].as_bytes()));
    }

    #[test]
    fn unknown_native_entry_stays_resident_and_cannot_be_retried() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("foreign-credential"), b"data").unwrap();
        let file = File::open(directory.path()).unwrap();
        let mut original = Entries::new();

        assert!(!original.observe(&file, &[true; NAMES.len()]));
        assert!(
            original
                .retained_names()
                .contains(&b"foreign-credential".as_slice())
        );

        std::fs::remove_file(directory.path().join("foreign-credential")).unwrap();
        assert!(!original.observe(&file, &[true; NAMES.len()]));
        assert!(
            original
                .retained_names()
                .contains(&b"foreign-credential".as_slice())
        );
    }

    #[test]
    fn optional_native_names_match_the_exact_selected_roster() {
        for mask in 0_u16..4096 {
            let mut selected = [true; NAMES.len()];
            selected[7] = mask & 1 != 0;
            selected[8] = mask & 2 != 0;
            selected[9] = selected[8];
            selected[15] = selected[8];
            selected[16] = selected[8];
            selected[20..24].fill(mask & 2 != 0);
            selected[12] = mask & 4 != 0;
            selected[13] = mask & 8 != 0;
            selected[14] = mask & 16 != 0;
            selected[24] = mask & 32 != 0;
            selected[25] = mask & 64 != 0;
            selected[26] = mask & 128 != 0;
            selected[27] = mask & 256 != 0;
            selected[28] = selected[27];
            selected[29] = mask & 512 != 0;
            selected[30] = mask & 1024 != 0;
            selected[31] = mask & 2048 != 0;
            let directory = tempfile::tempdir().unwrap();
            for (index, name) in NAMES.iter().enumerate() {
                if selected[index] {
                    std::fs::write(directory.path().join(name), b"data").unwrap();
                }
            }
            let mut original = Entries::new();
            assert!(original.observe(&File::open(directory.path()).unwrap(), &selected));

            // Neither appearance nor disappearance of a name is interchangeable
            // with the original configured roster, including required Root keys.
            for index in 7..NAMES.len() {
                let mut changed = selected;
                changed[index] = !changed[index];
                let mut original = Entries::new();
                assert!(!original.observe(&File::open(directory.path()).unwrap(), &changed));
            }
            for index in REQUIRED_CREDENTIAL_SLOTS {
                let mut changed = selected;
                changed[index] = false;
                let mut original = Entries::new();
                assert!(!original.observe(&File::open(directory.path()).unwrap(), &changed));
                assert!(original.retained_names().is_empty());
            }
        }
    }
}
