//! Shares the ordinary and closed Runtime control-file observation recipe.

use std::os::fd::AsFd as _;
use std::path::Path;

use super::{
    CgroupLimitControlV1, LimitControlSlotV1, RetainedCgroupAnchor, is_missing,
    read_limit_record, validate_limit_record,
};
use crate::{Error, Result};

pub(super) fn capture_limit_control_slot_v1(
    anchor: &RetainedCgroupAnchor,
    control: CgroupLimitControlV1,
    slot: &mut LimitControlSlotV1,
) -> Result<()> {
    capture_limit_control_slot_with_native_disposition_v4(anchor, control, slot, false)
}

pub(super) fn capture_limit_control_slot_with_native_disposition_v4(
    anchor: &RetainedCgroupAnchor,
    control: CgroupLimitControlV1,
    slot: &mut LimitControlSlotV1,
    retire_completed_names: bool,
) -> Result<()> {
    let path = Path::new(control.name());
    match anchor.root.open_regular_retaining(path, &mut slot.opening) {
        Err(error @ Error::Syscall { .. }) if is_missing(&error) => {
            slot.absent = Some(error);
            match anchor.root.open_regular_retaining(path, &mut slot.bookend) {
                Err(error) if is_missing(&error) => {
                    slot.absence_bookend = Some(error);
                    return Ok(());
                }
                Err(error) => return Err(error),
                Ok(()) => return Err(Error::invalid("cgroup control", "absent file appeared")),
            }
        }
        Err(error) => return Err(error),
        Ok(()) => {}
    }

    // The same readable OFD supplies every byte, from offset zero. The
    // sentinel and each returned prefix are resident before validation.
    read_limit_record(slot.opening.file()?.as_fd(), &mut slot.bytes, &mut slot.length)?;
    validate_limit_record(control, &slot.bytes[..slot.length])?;
    anchor.root.open_regular_retaining(path, &mut slot.bookend)?;
    if slot.opening.file()?.identity() != slot.bookend.file()?.identity() {
        return Err(Error::invalid("cgroup control", "named identity changed"));
    }
    if retire_completed_names {
        // Only the accepted identity DATA is needed by later checks. The
        // original readable OFD stays for the final same-OFD byte comparison.
        slot.bookend_disposed = Some(slot.bookend.file()?.identity());
        drop(slot.bookend.take_readable_file());
    }
    Ok(())
}

pub(super) fn recheck_limit_control_slot_v1(
    anchor: &RetainedCgroupAnchor,
    control: CgroupLimitControlV1,
    slot: &mut LimitControlSlotV1,
) -> Result<()> {
    recheck_limit_control_slot_with_native_disposition_v4(anchor, control, slot, false)
}

pub(super) fn recheck_limit_control_slot_with_native_disposition_v4(
    anchor: &RetainedCgroupAnchor,
    control: CgroupLimitControlV1,
    slot: &mut LimitControlSlotV1,
    retire_completed_names: bool,
) -> Result<()> {
    let path = Path::new(control.name());
    if slot.absent.is_some() {
        match anchor.root.open_regular_retaining(path, &mut slot.final_name) {
            Err(error) if is_missing(&error) => {
                slot.final_absence = Some(error);
                return Ok(());
            }
            Err(error) => return Err(error),
            Ok(()) => return Err(Error::invalid("cgroup control", "absent file appeared")),
        }
    }
    read_limit_record(
        slot.opening.file()?.as_fd(), &mut slot.final_bytes, &mut slot.final_length,
    )?;
    if slot.bytes[..slot.length] != slot.final_bytes[..slot.final_length] {
        return Err(Error::invalid("cgroup control", "same-OFD record changed"));
    }
    anchor.root.open_regular_retaining(path, &mut slot.final_name)?;
    if slot.opening.file()?.identity() != slot.final_name.file()?.identity() {
        return Err(Error::invalid("cgroup control", "final named identity changed"));
    }
    if retire_completed_names {
        slot.final_name_disposed = Some(slot.final_name.file()?.identity());
        drop(slot.final_name.take_readable_file());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use crate::path::BeneathRoot;

    // This fixture exercises only the regular-file comparison kernel. It does
    // not pass the cgroup admission engine or construct any production grant.
    fn fixture(path: &Path) -> RetainedCgroupAnchor {
        let root = BeneathRoot::from_owned(File::open(path).unwrap().into()).unwrap();
        RetainedCgroupAnchor { kernel_id: root.identity().inode, root }
    }

    #[test]
    fn selected_name_checks_close_only_the_compared_files_and_keep_the_original_ofd() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("pids.max"), b"12\n").unwrap();
        let anchor = fixture(directory.path());
        let mut slot = LimitControlSlotV1::default();

        capture_limit_control_slot_with_native_disposition_v4(
            &anchor, CgroupLimitControlV1::PidsMax, &mut slot, true,
        ).unwrap();
        let identity = slot.opening.file().unwrap().identity();

        assert_eq!(slot.bookend_disposed, Some(identity));
        assert!(slot.bookend.file().is_err());
        assert!(rustix::fs::fstat(slot.opening.file().unwrap().as_fd()).is_ok());
        recheck_limit_control_slot_with_native_disposition_v4(
            &anchor, CgroupLimitControlV1::PidsMax, &mut slot, true,
        ).unwrap();
        assert_eq!(slot.final_name_disposed, Some(identity));
        assert!(slot.final_name.file().is_err());
        assert_eq!(slot.opening.file().unwrap().identity(), identity);
        assert_eq!(&slot.final_bytes[..slot.final_length], b"12\n");
    }

    #[test]
    fn ordinary_retains_its_existing_names_and_changed_selected_ofd_stays_resident() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pids.max");
        std::fs::write(&path, b"12\n").unwrap();
        let anchor = fixture(directory.path());
        let mut ordinary = LimitControlSlotV1::default();
        capture_limit_control_slot_v1(&anchor, CgroupLimitControlV1::PidsMax, &mut ordinary).unwrap();
        recheck_limit_control_slot_v1(&anchor, CgroupLimitControlV1::PidsMax, &mut ordinary).unwrap();
        assert!(ordinary.bookend.file().is_ok());
        assert!(ordinary.final_name.file().is_ok());
        assert!(ordinary.bookend_disposed.is_none());
        assert!(ordinary.final_name_disposed.is_none());

        let mut selected = LimitControlSlotV1::default();
        capture_limit_control_slot_with_native_disposition_v4(
            &anchor, CgroupLimitControlV1::PidsMax, &mut selected, true,
        ).unwrap();
        let identity = selected.opening.file().unwrap().identity();
        std::fs::write(&path, b"13\n").unwrap();
        assert!(recheck_limit_control_slot_with_native_disposition_v4(
            &anchor, CgroupLimitControlV1::PidsMax, &mut selected, true,
        ).is_err());

        assert_eq!(selected.opening.file().unwrap().identity(), identity);
        assert!(rustix::fs::fstat(selected.opening.file().unwrap().as_fd()).is_ok());
        assert!(selected.final_name_disposed.is_none());
        assert_eq!(&selected.final_bytes[..selected.final_length], b"13\n");
    }
}
