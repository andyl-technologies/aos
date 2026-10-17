//! Tracks process-private descriptor identity before inherited native close custody.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

#[derive(Clone, Copy)]
pub(super) struct DescriptorAlias {
    descriptor: i32,
    device: u64,
    inode: u64,
    mode: u32,
    special_device: u64,
}

impl DescriptorAlias {
    pub(super) fn capture(descriptor: i32) -> io::Result<Self> {
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat initializes this stack value on success and retains no pointer.
        if unsafe { libc::fstat(descriptor, status.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstat initialized every field inspected below.
        let status = unsafe { status.assume_init() };
        Ok(Self {
            descriptor,
            device: status.st_dev,
            inode: status.st_ino,
            mode: status.st_mode,
            special_device: status.st_rdev,
        })
    }

    fn matches(self) -> io::Result<bool> {
        let current = Self::capture(self.descriptor)?;
        Ok(self.device == current.device
            && self.inode == current.inode
            && self.mode == current.mode
            && self.special_device == current.special_device)
    }
}

/// Records authenticated native source aliases before Rust duplicates them.
///
/// # Errors
/// Refuses unavailable descriptor identity or conflicting inherited custody.
pub(crate) fn retain_source_alias(descriptor: i32) -> Result<(), RamError> {
    let alias = DescriptorAlias::capture(descriptor)?;
    let controller = controller()?.ok_or("RAM controller unavailable")?;
    let mut state = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM alias custody poisoned"))?;
    if state.aliases[..2]
        .iter()
        .flatten()
        .any(|other| other.descriptor == descriptor)
    {
        return Err(RamError::Invariant(
            "source alias conflicts with control/backing",
        ));
    }
    if let Some(old) = state.aliases[2]
        && (old.descriptor != descriptor || !old.matches()?)
    {
        return Err(RamError::Invariant("source alias custody changed"));
    }
    state.aliases[2] = Some(alias);
    Ok(())
}

/// Transfers only still-authenticated inherited launch aliases to native close custody.
///
/// # Errors
/// Refuses descriptor reuse or uncertain operational ownership; closes nothing.
pub(crate) fn disarm_inherited_aliases() -> Result<[Option<i32>; 3], RamError> {
    let controller = controller()?.ok_or("RAM controller unavailable")?;
    let mut state = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM alias custody poisoned"))?;
    for alias in state.aliases.iter().flatten() {
        if !alias.matches()? {
            return Err(RamError::Invariant("inherited alias descriptor reused"));
        }
    }
    let aliases = state
        .aliases
        .map(|alias| alias.map(|alias| alias.descriptor));
    state.aliases = [None; 3];
    Ok(aliases)
}
