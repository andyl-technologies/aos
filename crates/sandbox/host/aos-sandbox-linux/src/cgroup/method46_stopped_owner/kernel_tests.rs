//! Exercises the fixed stopped-owner native recipe in the AOS cgroup-v2 VM.
//!
//! The minimal guest has no installed Controller or Storage owners. These
//! kernel observations qualify the reader, without authenticating a startup
//! Source, excluding service jobs or granting protected journal/TPM custody.

use std::fs::{self, File};
use std::process::Command;

use super::*;

#[test]
fn fixed_stopped_owners_retain_absence_empty_and_recursive_population() {
    let hierarchy = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").unwrap().into()).unwrap();
    let control = Path::new("/sys/fs/cgroup/aos.slice/aos-control.slice");
    let aggregate = control.join("aos-control-storage.slice");
    // This test runs before any service-shaped fixture in the minimal VM.
    // Refuse existing names rather than adopting or removing another owner.
    assert!(!Path::new("/sys/fs/cgroup/aos.slice").exists());
    fs::create_dir("/sys/fs/cgroup/aos.slice").unwrap();
    fs::create_dir(control).unwrap();
    fs::create_dir(&aggregate).unwrap();

    for owner in [
        Method46StoppedOwnerCgroupV1::Controller,
        Method46StoppedOwnerCgroupV1::Storage(StorageCgroupLayoutV1::Ordinary),
        Method46StoppedOwnerCgroupV1::Storage(StorageCgroupLayoutV1::ReceivingAggregate),
    ] {
        let path = Path::new("/sys/fs/cgroup").join(owner.relative());
        let mut absent = Method46StoppedOwnerCgroupOriginalV1::new();

        absent.observe_once_v1(&hierarchy, owner).unwrap();

        assert!(absent.is_empty_or_absent_data_v1());
        assert!(absent.original.absence().is_some());
        assert!(absent.original.anchor.is_none());

        fs::create_dir(&path).unwrap();
        let mut empty = Method46StoppedOwnerCgroupOriginalV1::new();
        empty.observe_once_v1(&hierarchy, owner).unwrap();

        assert!(empty.is_empty_or_absent_data_v1());
        assert_eq!(empty.population.state(), Some(CgroupPopulationState::Empty));
        assert!(empty.original.events.is_some());
        assert!(
            empty
                .original
                .probes
                .iter()
                .all(|probe| probe.file().is_ok())
        );

        let descendant = path.join("member");
        fs::create_dir(&descendant).unwrap();
        let mut process = Command::new(std::env::var_os("AOS_CGROUP_TEST_SLEEP").unwrap())
            .arg("30")
            .spawn()
            .unwrap();
        fs::write(descendant.join("cgroup.procs"), process.id().to_string()).unwrap();
        let mut populated = Method46StoppedOwnerCgroupOriginalV1::new();

        assert!(populated.observe_once_v1(&hierarchy, owner).is_err());

        assert!(!populated.is_empty_or_absent_data_v1());
        assert_eq!(
            populated.population.state(),
            Some(CgroupPopulationState::Populated)
        );
        let first = populated.failure_v1().unwrap() as *const dyn std::error::Error as *const ();
        process.kill().unwrap();
        process.wait().unwrap();
        fs::remove_dir(&descendant).unwrap();

        // Actual later emptiness cannot replace the failed original. A fresh
        // independent observation is needed and retains its own native result.
        assert!(populated.observe_once_v1(&hierarchy, owner).is_err());
        assert_eq!(
            populated.failure_v1().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        let mut after = Method46StoppedOwnerCgroupOriginalV1::new();
        after.observe_once_v1(&hierarchy, owner).unwrap();
        assert!(after.is_empty_or_absent_data_v1());

        fs::remove_dir(&path).unwrap();
        let mut removed = Method46StoppedOwnerCgroupOriginalV1::new();
        removed.observe_once_v1(&hierarchy, owner).unwrap();
        assert!(removed.is_empty_or_absent_data_v1());
        assert!(removed.original.absence().is_some());
        assert!(!populated.is_empty_or_absent_data_v1());
    }

    fs::remove_dir(aggregate).unwrap();
    fs::remove_dir(control).unwrap();
    fs::remove_dir("/sys/fs/cgroup/aos.slice").unwrap();
}
