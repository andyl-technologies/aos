//! Retains refused native cuts from the sole canary public-file recipe.
//!
//! The ordinary adapter and funded adapter use identical syscalls, predicates
//! and short-circuit order. A completed positive cut releases its temporary
//! native evidence; a refused cut stays beside the original credential File.

use super::{CanaryPublicInputCauseV2, PublicFileIdentityV2, CANARY_CREDENTIAL_CONTEXT_V2};
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;

pub(super) struct CanaryPublicNativeCutV3 {
    metadata: Option<std::fs::Metadata>,
    stat: Option<rustix::fs::Stat>,
    vfs: Option<rustix::fs::StatVfs>,
    flags: Option<rustix::fs::OFlags>,
    context: [u8; 256],
    context_result: Option<Result<usize, rustix::io::Errno>>,
    acl: [u8; 4096],
    acl_results: [Option<Result<usize, rustix::io::Errno>>; 2],
}

impl std::fmt::Debug for CanaryPublicNativeCutV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CanaryPublicNativeCutV3")
            .field("metadata", &self.metadata.is_some())
            .field("stat", &self.stat.is_some())
            .field("vfs", &self.vfs.is_some())
            .field("flags", &self.flags.is_some())
            .field("context_result", &self.context_result)
            .field("acl_results", &self.acl_results)
            .finish_non_exhaustive()
    }
}

impl CanaryPublicNativeCutV3 {
    fn new() -> Self {
        Self {
            metadata: None, stat: None, vfs: None, flags: None,
            context: [0; 256], context_result: None,
            acl: [0; 4096], acl_results: [None; 2],
        }
    }
}

// The private disposition flag comes only from the actual already-entered
// funded delivery arm. It changes custody, never file admission or authority.
fn cut_v3<T>(retained: bool, observe: impl FnOnce(&mut CanaryPublicNativeCutV3)
    -> Result<T, CanaryPublicInputCauseV2>) -> Result<T, CanaryPublicInputCauseV2>
{
    let mut original = CanaryPublicNativeCutV3::new();
    match observe(&mut original) {
        Ok(value) => Ok(value),
        Err(cause) if retained => Err(CanaryPublicInputCauseV2::NativeCut {
            cause: Box::new(cause), original: Box::new(original),
        }),
        Err(cause) => Err(cause),
    }
}

/// Returns only compiled representation bytes; these locals own no namespace.
pub(super) fn receiving_bytes_v3() -> Option<usize> {
    // First refusal and four independently retained post causes may coexist.
    // Include the two Box bodies/allocator alignment and construction carriers.
    let cut = std::mem::size_of::<CanaryPublicNativeCutV3>()
        .checked_add(std::mem::size_of::<CanaryPublicInputCauseV2>())?
        .checked_add(2_usize.checked_mul(3 * std::mem::size_of::<usize>())?)?;
    cut.checked_mul(5)?.checked_mul(3)
}

fn identity_cut_v3(file: &File, expected: Option<Option<PublicFileIdentityV2>>, retained: bool) -> Result<PublicFileIdentityV2, CanaryPublicInputCauseV2> {
    cut_v3(retained, |original| {
        original.metadata = Some(file.metadata()?);
        let metadata = original.metadata.as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
        let identity = (
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid(),
            metadata.gid(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec()
        );
        if expected.is_some_and(|before| before != Some(identity)) {
            return Err(CanaryPublicInputCauseV2::Changed);
        }
        Ok(identity)
    })
}

pub(super) fn identity_v3(file: &File, retained: bool)
    -> Result<PublicFileIdentityV2, CanaryPublicInputCauseV2>
{
    identity_cut_v3(file, None, retained)
}

pub(super) fn require_identity_v3(file: &File, expected: Option<PublicFileIdentityV2>, retained: bool)
    -> Result<(), CanaryPublicInputCauseV2>
{
    identity_cut_v3(file, Some(expected), retained).map(|_| ())
}


pub(super) fn ancestry_v3(
    slots: &mut [Option<File>; 7],
    retained: bool,
) -> Result<(), CanaryPublicInputCauseV2> {
    if slots.iter().any(Option::is_some) {
        return Err(CanaryPublicInputCauseV2::Changed);
    }
    let flags = rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    slots[0] = Some(File::from(rustix::fs::open("/", flags, rustix::fs::Mode::empty())?));
    let names = ["run", "credentials", "aos-storaged.service"];
    for index in 0..4 {
        let file = slots[index].as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
        cut_v3(retained, |original| {
            original.stat = Some(rustix::fs::fstat(file)?);
            let stat = original.stat.as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
            if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o022 != 0 {
                return Err(CanaryPublicInputCauseV2::Changed);
            }
            Ok(())
        })?;
        if index < names.len() {
            slots[index + 1] = Some(File::from(rustix::fs::openat(
                file, names[index], flags, rustix::fs::Mode::empty(),
            )?));
        }
    }
    Ok(())
}


pub(super) fn protection_v3(
    file: &File,
    leaf_bytes: Option<usize>,
    retained: bool,
) -> Result<(), CanaryPublicInputCauseV2> {
    cut_v3(retained, |original| {
        original.stat = Some(rustix::fs::fstat(file)?);
        let stat = original.stat.as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
        let expected = if leaf_bytes.is_some() {
            0o400
        } else {
            0o500
        };
        let kind = if leaf_bytes.is_some() {
            rustix::fs::FileType::RegularFile
        } else {
            rustix::fs::FileType::Directory
        };
        if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o7777 != expected
            || rustix::fs::FileType::from_raw_mode(stat.st_mode) != kind
            || leaf_bytes.is_some_and(|width| stat.st_size != width as i64 || stat.st_nlink != 1)
        {
            return Err(CanaryPublicInputCauseV2::Changed);
        }
        original.vfs = Some(rustix::fs::fstatvfs(file)?);
        if !original.vfs.as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?
            .f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY)
        {
            return Err(CanaryPublicInputCauseV2::Changed);
        }
        if leaf_bytes.is_some() {
            original.flags = Some(rustix::fs::fcntl_getfl(file)?);
            let flags = original.flags.ok_or(CanaryPublicInputCauseV2::Changed)?;
            if flags.contains(rustix::fs::OFlags::PATH)
                || flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
            {
                return Err(CanaryPublicInputCauseV2::Changed);
            }
        }
        original.context_result = Some(rustix::fs::fgetxattr(file, "security.selinux", &mut original.context));
        let count = original.context_result.ok_or(CanaryPublicInputCauseV2::Changed)??;
        let actual = original.context[..count].strip_suffix(&[0]).unwrap_or(&original.context[..count]);
        if actual != CANARY_CREDENTIAL_CONTEXT_V2 {
            return Err(CanaryPublicInputCauseV2::Changed);
        }
        for (index, name) in ["system.posix_acl_access", "system.posix_acl_default"].into_iter().enumerate() {
            original.acl_results[index] = Some(rustix::fs::fgetxattr(file, name, &mut original.acl));
            match original.acl_results[index].ok_or(CanaryPublicInputCauseV2::Changed)? {
                Err(rustix::io::Errno::NODATA) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(CanaryPublicInputCauseV2::Changed),
            }
        }
        Ok(())
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_protection_keeps_stat_before_any_later_probe() {
        let file = File::open("/dev/null").unwrap();
        let refusal = protection_v3(&file, Some(0), true).unwrap_err();
        let CanaryPublicInputCauseV2::NativeCut { cause, original } = &refusal else {
            panic!("selected refusal must retain its actual native cut");
        };
        assert!(matches!(cause.as_ref(), CanaryPublicInputCauseV2::Changed));
        assert!(original.stat.is_some());
        assert!(original.vfs.is_none());
        assert!(original.flags.is_none());
        assert!(original.context_result.is_none());
        assert!(original.acl_results.iter().all(Option::is_none));

        let ordinary = protection_v3(&file, Some(0), false).unwrap_err();
        assert!(matches!(ordinary, CanaryPublicInputCauseV2::Changed));
        assert!(original.stat.is_some());
    }

    #[test]
    fn failed_identity_comparison_keeps_the_actual_metadata() {
        let file = File::open("/dev/null").unwrap();
        let before = identity_v3(&file, false).unwrap();
        let mut substituted = before;
        substituted.1 = substituted.1.wrapping_add(1);

        let refusal = require_identity_v3(&file, Some(substituted), true).unwrap_err();
        let CanaryPublicInputCauseV2::NativeCut { cause, original } = &refusal else {
            panic!("failed comparison must retain the actual Metadata");
        };
        assert!(matches!(cause.as_ref(), CanaryPublicInputCauseV2::Changed));
        let metadata = original.metadata.as_ref().unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), (before.0, before.1));
        assert!(original.stat.is_none());
    }
}
