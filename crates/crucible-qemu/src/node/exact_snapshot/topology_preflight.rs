//! Descriptor authentication before destination graph capacity admission.

use std::os::fd::BorrowedFd;

use crucible_ram::{Limits, RootRecord, Scope};
use rustix::fs::fstat;
use rustix::io::pread;

use crate::{QemuNodeChannelError, QmpCheckpointTopology};

pub(super) fn read_capture_topology(
    descriptor: BorrowedFd<'_>,
    report: QmpCheckpointTopology,
) -> Result<RootRecord, QemuNodeChannelError> {
    let rejected = |message: String| {
        QemuNodeChannelError::new("authenticate checkpoint topology descriptor", message)
    };
    if report.generation == 0
        || !(1..=QmpCheckpointTopology::MAX_RECORD_BYTES).contains(&report.root_bytes)
    {
        return Err(rejected("invalid topology preparation bounds".into()));
    }
    let metadata = fstat(descriptor).map_err(|error| rejected(error.to_string()))?;
    if metadata.st_size < 0 || metadata.st_size as u64 != report.root_bytes as u64 {
        return Err(rejected(
            "descriptor length differs from topology report".into(),
        ));
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(report.root_bytes)
        .map_err(|error| rejected(error.to_string()))?;
    encoded.resize(report.root_bytes, 0);
    let mut copied = 0;
    while copied < encoded.len() {
        match pread(descriptor, &mut encoded[copied..], copied as u64) {
            Ok(0) => return Err(rejected("truncated topology descriptor".into())),
            Ok(count) => copied += count,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(rejected(error.to_string())),
        }
    }
    let record = RootRecord::decode(&encoded, Limits::default())
        .map_err(|error| rejected(error.to_string()))?;
    if record.scope() != Scope::Exact
        || record.digest().as_bytes() != &report.root.bytes
        || record.topology().digest().as_bytes() != &report.topology.bytes
    {
        return Err(rejected(
            "topology record scope or digest differs from report".into(),
        ));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;

    fn fixture() -> (std::fs::File, QmpCheckpointTopology) {
        let topology = crucible_ram::Topology::new(
            vec![
                crucible_ram::RegionDescriptor::new(
                    "ram",
                    crucible_ram::RegionClass::MutableMain,
                    4099,
                )
                .unwrap_or_else(|error| panic!("fixture region: {error}")),
            ],
            Limits::default(),
        )
        .unwrap_or_else(|error| panic!("fixture topology: {error}"));
        let tree =
            crucible_ram::RegionTree::zeroed(4099, &crucible_ram::MetadataBudget::new(65_536))
                .unwrap_or_else(|error| panic!("fixture page tree: {error}"));
        let record = RootRecord::new(topology, Scope::Exact, vec![tree.digest()])
            .unwrap_or_else(|error| panic!("fixture root record: {error}"));
        let encoded = record.encode();
        let mut file =
            tempfile::tempfile().unwrap_or_else(|error| panic!("fixture descriptor: {error}"));
        file.write_all(&encoded)
            .unwrap_or_else(|error| panic!("fixture descriptor contents: {error}"));
        let report = QmpCheckpointTopology {
            generation: 17,
            root_bytes: encoded.len(),
            root: crucible::ContentHash {
                bytes: *record.digest().as_bytes(),
            },
            topology: crucible::ContentHash {
                bytes: *record.topology().digest().as_bytes(),
            },
        };
        (file, report)
    }

    #[test]
    fn descriptor_topology_is_authenticated_before_backend_callback() {
        let (file, report) = fixture();
        let record = read_capture_topology(file.as_fd(), report)
            .unwrap_or_else(|error| panic!("authenticate topology: {error}"));
        assert_eq!(record.topology().total_logical_bytes(), 4099);
        for malformed in [
            QmpCheckpointTopology {
                generation: 0,
                ..report
            },
            QmpCheckpointTopology {
                root_bytes: usize::MAX,
                ..report
            },
            QmpCheckpointTopology {
                root_bytes: report.root_bytes + 1,
                ..report
            },
            QmpCheckpointTopology {
                topology: crucible::ContentHash { bytes: [0; 32] },
                ..report
            },
            QmpCheckpointTopology {
                root: crucible::ContentHash { bytes: [0; 32] },
                ..report
            },
        ] {
            assert!(read_capture_topology(file.as_fd(), malformed).is_err());
        }
    }
}
