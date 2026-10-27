//! Backing storage for copy-on-write overlay pages.
//!
//! A [`BlockPageStore`] owns the bytes of every 4 KiB page an overlay has
//! copied up. Production devices back it with a private, unnamed file in the
//! run's quota-accounted directory, so overlay content occupies disk rather
//! than heap. Tests and in-process doubles may use the heap backend, which has
//! identical semantics.
//!
//! Pages are immutable once shared. Each page is a `PageRef`, a reference-
//! counted handle to one slot. Cloning an overlay or freezing it into a
//! snapshot shares the handles; a later write to a shared page allocates a new
//! slot instead of mutating the old one, so the prior state stays exact. A
//! write to a page no other overlay holds patches its slot in place. When the
//! last handle to a slot drops, the slot returns to the store's free list and
//! is reused by the next allocation. Slot numbers never influence any guest-
//! visible byte, response, snapshot, or identity.
//!
//! ```text
//! file backend:  slot n occupies bytes [n * 4096, (n + 1) * 4096)
//! allocate():    pop a free slot, else extend the high-water mark
//! drop(last):    push the slot onto the free list
//! ```

use std::fmt;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex, PoisonError};

use super::overlay::PAGE_SIZE;

const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

/// The owner of copied-up overlay page bytes.
///
/// Cloning a store yields another handle to the same backing; it never copies
/// page bytes. Every overlay created over a store allocates its new pages
/// there. See the [module documentation](self) for the sharing rules.
#[derive(Clone)]
pub struct BlockPageStore {
    backing: Backing,
}

#[derive(Clone)]
enum Backing {
    Memory,
    File(Arc<FileBacking>),
}

impl BlockPageStore {
    /// Returns a heap-backed store.
    ///
    /// Heap pages behave exactly like file pages. Use this for tests and
    /// in-process doubles; production devices use [`Self::from_unnamed_file`].
    #[must_use]
    pub fn memory() -> Self {
        Self {
            backing: Backing::Memory,
        }
    }

    /// Returns a store backed by an empty, private file.
    ///
    /// The caller creates `file` in the run's quota-accounted directory,
    /// typically with `O_TMPFILE` so it has no name and disappears when the
    /// last handle closes. The store takes exclusive ownership of its bytes;
    /// nothing else may read or write the file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be inspected or is not empty.
    pub fn from_unnamed_file(file: File) -> io::Result<Self> {
        if file.metadata()?.len() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block page store file must start empty",
            ));
        }
        Ok(Self {
            backing: Backing::File(Arc::new(FileBacking {
                file,
                slots: Mutex::new(SlotAllocator::default()),
            })),
        })
    }

    /// Returns `true` when this store keeps page bytes on the heap.
    #[must_use]
    pub fn is_memory(&self) -> bool {
        matches!(self.backing, Backing::Memory)
    }

    /// Returns the number of page slots currently live in a file store.
    ///
    /// A heap store reports zero; its pages are ordinary allocations.
    #[must_use]
    pub fn live_file_slots(&self) -> u64 {
        match &self.backing {
            Backing::Memory => 0,
            Backing::File(file) => file.live_slots(),
        }
    }

    /// Stores one page and returns its sole handle.
    pub(crate) fn allocate(&self, page: &[u8; PAGE_SIZE]) -> io::Result<PageRef> {
        let slot = match &self.backing {
            Backing::Memory => PageSlot::Memory(Box::new(*page)),
            Backing::File(file) => {
                let slot = file.acquire()?;
                // Construct the handle first so a failed write releases the slot.
                let slot = PageSlot::File {
                    backing: Arc::clone(file),
                    slot,
                };
                slot.write_at(0, page)?;
                slot
            }
        };
        Ok(PageRef(Arc::new(slot)))
    }
}

impl fmt::Debug for BlockPageStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.backing {
            Backing::Memory => formatter.write_str("BlockPageStore::Memory"),
            Backing::File(file) => formatter
                .debug_struct("BlockPageStore::File")
                .field("live_slots", &file.live_slots())
                .finish(),
        }
    }
}

struct FileBacking {
    file: File,
    slots: Mutex<SlotAllocator>,
}

#[derive(Default)]
struct SlotAllocator {
    high_water: u64,
    free: Vec<u64>,
}

impl FileBacking {
    fn acquire(&self) -> io::Result<u64> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = slots.free.pop() {
            return Ok(slot);
        }
        let slot = slots.high_water;
        slots.high_water = slot.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "block page store is exhausted")
        })?;
        Ok(slot)
    }

    fn release(&self, slot: u64) {
        // The allocator holds plain integers, so a poisoned lock is still
        // consistent; recover it rather than leaking the slot.
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.free.push(slot);
    }

    fn live_slots(&self) -> u64 {
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots
            .high_water
            .saturating_sub(u64::try_from(slots.free.len()).unwrap_or(u64::MAX))
    }
}

enum PageSlot {
    Memory(Box<[u8; PAGE_SIZE]>),
    File {
        backing: Arc<FileBacking>,
        slot: u64,
    },
}

impl PageSlot {
    fn file_offset(slot: u64, offset: usize) -> io::Result<u64> {
        slot.checked_mul(PAGE_SIZE_U64)
            .and_then(|base| base.checked_add(offset as u64))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "page slot overflows"))
    }

    fn read_at(&self, offset: usize, output: &mut [u8]) -> io::Result<()> {
        check_page_range(offset, output.len())?;
        match self {
            Self::Memory(page) => {
                output.copy_from_slice(&page[offset..offset + output.len()]);
                Ok(())
            }
            Self::File { backing, slot } => backing
                .file
                .read_exact_at(output, Self::file_offset(*slot, offset)?),
        }
    }

    fn write_at(&self, offset: usize, input: &[u8]) -> io::Result<()> {
        check_page_range(offset, input.len())?;
        match self {
            Self::Memory(_) => Err(io::Error::other(
                "heap pages are patched through the exclusive handle",
            )),
            Self::File { backing, slot } => backing
                .file
                .write_all_at(input, Self::file_offset(*slot, offset)?),
        }
    }
}

impl Drop for PageSlot {
    fn drop(&mut self) {
        if let Self::File { backing, slot } = self {
            backing.release(*slot);
        }
    }
}

fn check_page_range(offset: usize, length: usize) -> io::Result<()> {
    if offset.checked_add(length).is_none_or(|end| end > PAGE_SIZE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "page access exceeds the page",
        ));
    }
    Ok(())
}

/// A shared handle to one stored overlay page.
///
/// Equality of handles is identity, not content; overlays compare content
/// through their chunk identities.
#[derive(Clone)]
pub(crate) struct PageRef(Arc<PageSlot>);

impl PageRef {
    /// Reads `output.len()` bytes starting at `offset` within the page.
    pub(crate) fn read_at(&self, offset: usize, output: &mut [u8]) -> io::Result<()> {
        self.0.read_at(offset, output)
    }

    /// Reads the complete page.
    pub(crate) fn read_page(&self) -> io::Result<[u8; PAGE_SIZE]> {
        let mut page = [0_u8; PAGE_SIZE];
        self.read_at(0, &mut page)?;
        Ok(page)
    }

    /// Returns `true` when both handles name the same stored slot.
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Patches the page in place when this is its only handle.
    ///
    /// Returns `Ok(false)` without changing anything when another overlay or
    /// snapshot still shares the page; the caller must then copy it.
    pub(crate) fn patch_if_unique(&mut self, offset: usize, input: &[u8]) -> io::Result<bool> {
        check_page_range(offset, input.len())?;
        let Some(slot) = Arc::get_mut(&mut self.0) else {
            return Ok(false);
        };
        match slot {
            PageSlot::Memory(page) => {
                page[offset..offset + input.len()].copy_from_slice(input);
            }
            PageSlot::File { .. } => slot.write_at(offset, input)?,
        }
        Ok(true)
    }
}

impl fmt::Debug for PageRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.as_ref() {
            PageSlot::Memory(_) => formatter.write_str("PageRef::Memory"),
            PageSlot::File { slot, .. } => write!(formatter, "PageRef::File({slot})"),
        }
    }
}
