//! Owns the actual marker read across later physical comparison failures.
//!
//! The ordinary adapter uses this same recipe and consumes its file at the
//! original read boundary. The retaining adapter keeps the opened marker and
//! root descriptor on the caller's already-paid destination. It supplies no
//! path authority, budget, tree exclusion, or positive native disposition.

use super::*;
use std::os::fd::OwnedFd;

use crate::guest_root_label::GuestRootLabelErrorV1;
use aos_sandbox_guest_root_measurement::guest_root_tree::GuestRootTreeErrorV1;

#[derive(Clone, Copy)]
enum Failure {
    Directory,
    Open,
    Metadata,
    Read,
    Invalid,
    Tree,
    Root,
    Labels,
}

/// Retains one marker's native inputs and the first physical failure.
///
/// Construction is inert. Callers must fund this owner and its descriptor and
/// buffer peak before invoking the reader. The owner is not proof of payment
/// or permission to inspect either supplied path.
pub struct GuestRootMarkerReadOriginalV1 {
    // Raw bytes precede descriptors so they dispose before those descriptors.
    bytes: Vec<u8>,
    directory: Option<std::io::Result<fs::Metadata>>,
    opened: Option<std::io::Result<File>>,
    metadata: Option<std::io::Result<fs::Metadata>>,
    read: Option<std::io::Result<usize>>,
    tree: Option<Result<[u8; 32], GuestRootTreeErrorV1>>,
    root: Option<Result<OwnedFd, rustix::io::Errno>>,
    labels: Option<Result<(), GuestRootLabelErrorV1>>,
    retained_labels: Option<crate::guest_root_label::GuestRootLabelReadOriginalV1>,
    retained_label_result: Option<Result<(), crate::guest_root_label::GuestRootLabelReadClosedV1>>,
    first: Option<Failure>,
    entered: bool,
}

impl GuestRootMarkerReadOriginalV1 {
    /// Creates an empty destination without opening or decoding anything.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            directory: None,
            opened: None,
            metadata: None,
            read: None,
            tree: None,
            root: None,
            labels: None, retained_labels: None, retained_label_result: None,
            first: None,
            entered: false,
        }
    }

    /// Runs the existing marker recipe while retaining reached native owners.
    ///
    /// # Errors
    /// Returns the existing publication refusal projection. The actual first
    /// native cause remains available through [`Self::failure`], along with
    /// the marker file and any completed root descriptor.
    pub fn read_once_v1(
        &mut self,
        template: &Path,
        workspace: &Path,
        expected: GuestRootPublicationProofV1,
    ) -> Result<(), GuestRootMarkerErrorV1> {
        self.read(template, workspace, expected, true, None)
    }

    /// Reads the same marker/tree with the complete label prefix retained.
    ///
    /// The real caller prepays the fixed label owner and uses the deny-only
    /// adapter to admit each reached native prefix before growth. Returning
    /// true cannot waive any marker, tree, label or native predicate.
    ///
    /// # Errors
    /// Refuses reentry or any unchanged marker/tree/label/native check, retaining
    /// the exact earlier source and every entered label-walk destination.
    pub fn read_receiving_projection_once_v2(
        &mut self, template: &Path, workspace: &Path, expected: GuestRootPublicationProofV1,
        admit: &mut impl FnMut(crate::guest_root_label::GuestRootLabelReadReachedDataV2) -> bool,
    ) -> Result<(), GuestRootMarkerErrorV1> {
        if self.entered {
            self.first.get_or_insert(Failure::Invalid);
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        }
        let (depth, entries) = crate::guest_root_label::GuestRootLabelReadOriginalV1::maximum_receiving_limits_v2();
        self.retained_labels = crate::guest_root_label::GuestRootLabelReadOriginalV1::with_receiving_limits_v2(depth, entries);
        if self.retained_labels.is_none() { return Err(GuestRootMarkerErrorV1::InvalidPublication); }
        self.read(template, workspace, expected, true, Some(admit))
    }

    /// Reports only the actual completed retained projection on this owner.
    #[must_use]
    pub fn retained_projection_completed_v2(&self) -> bool {
        self.entered && self.first.is_none()
            && matches!(self.retained_label_result, Some(Ok(())))
            && self.retained_labels.as_ref().is_some_and(
                crate::guest_root_label::GuestRootLabelReadOriginalV1::completed_exact_v1)
    }

    /// Reports denial only when it was the selected actual label-walk failure.
    #[must_use]
    pub fn retained_projection_admission_refused_v2(&self) -> bool {
        matches!(self.first, Some(Failure::Labels))
            && self.retained_labels.as_ref().and_then(|original| original.failure())
                .and_then(|cause| cause.downcast_ref::<crate::guest_root_label::GuestRootLabelErrorV1>())
                .is_some_and(|cause| matches!(cause, crate::guest_root_label::GuestRootLabelErrorV1::ReceivingAdmission))
    }

    /// Borrows the actual first native error without replacing its identity.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            Failure::Directory => error(&self.directory),
            Failure::Open => error(&self.opened),
            Failure::Metadata => error(&self.metadata),
            Failure::Read => error(&self.read),
            Failure::Tree => error(&self.tree),
            Failure::Root => error(&self.root),
            Failure::Labels => self.retained_labels.as_ref().and_then(
                crate::guest_root_label::GuestRootLabelReadOriginalV1::failure)
                .or_else(|| error(&self.retained_label_result)).or_else(|| error(&self.labels)),
            Failure::Invalid => None,
        }
    }

    pub(super) fn read_ordinary_v1(
        &mut self,
        template: &Path,
        workspace: &Path,
        expected: GuestRootPublicationProofV1,
    ) -> Result<(), GuestRootMarkerErrorV1> {
        self.read(template, workspace, expected, false, None).map_err(|projection| {
            // Ordinary I/O errors keep their old public class. Tree, root and
            // label failures keep their existing InvalidPublication mapping.
            let error = match self.first {
                Some(Failure::Directory) => self.directory.take().and_then(Result::err),
                Some(Failure::Open) => self.opened.take().and_then(Result::err),
                Some(Failure::Metadata) => self.metadata.take().and_then(Result::err),
                Some(Failure::Read) => self.read.take().and_then(Result::err),
                _ => None,
            };
            error.map(GuestRootMarkerErrorV1::Io).unwrap_or(projection)
        })
    }

    fn read(
        &mut self,
        template: &Path,
        workspace: &Path,
        expected: GuestRootPublicationProofV1,
        retaining: bool,
        admission: Option<&mut dyn FnMut(crate::guest_root_label::GuestRootLabelReadReachedDataV2) -> bool>,
    ) -> Result<(), GuestRootMarkerErrorV1> {
        if self.entered {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        }
        self.entered = true;
        let directory = marker_directory(workspace);
        self.first = Some(Failure::Directory);
        self.directory = Some(fs::symlink_metadata(&directory));
        let Some(Ok(metadata)) = self.directory.as_ref() else {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        };
        if let Err(error) = verify_directory_metadata(metadata) {
            self.first = Some(Failure::Invalid);
            return Err(error);
        }
        if !retaining {
            drop(self.directory.take());
        }
        let marker = directory.join(MARKER_FILE);
        self.first = Some(Failure::Open);
        self.opened = Some(OpenOptions::new().read(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC).open(&marker));
        let Some(Ok(file)) = self.opened.as_ref() else {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        };
        self.first = Some(Failure::Metadata);
        self.metadata = Some(file.metadata());
        let Some(Ok(metadata)) = self.metadata.as_ref() else {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        };
        if let Err(error) = verify_file(metadata) {
            self.first = Some(Failure::Invalid);
            return Err(error);
        }
        if !retaining {
            drop(self.metadata.take());
        }

        self.first = Some(Failure::Read);
        self.read = Some(if retaining {
            let Some(Ok(file)) = self.opened.as_mut() else {
                return Err(GuestRootMarkerErrorV1::InvalidPublication);
            };
            file.take(267).read_to_end(&mut self.bytes)
        } else {
            let Some(Ok(file)) = self.opened.take() else {
                return Err(GuestRootMarkerErrorV1::InvalidPublication);
            };
            // Taking the File itself preserves its original close-before-
            // decode boundary; selected reads borrow and retain that File.
            file.take(267).read_to_end(&mut self.bytes)
        });
        if !matches!(self.read, Some(Ok(_))) {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        }
        self.first = Some(Failure::Invalid);
        let observed = GuestRootPublicationProofV1::decode(&self.bytes)
            .map_err(|_| GuestRootMarkerErrorV1::InvalidPublication)?;
        if observed != expected {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        }
        self.first = Some(Failure::Tree);
        self.tree = Some(compare_guest_root_template_v1(template, workspace));
        let Some(Ok(measured)) = self.tree.as_ref() else {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        };
        if *measured != expected.root_tree_digest {
            self.first = Some(Failure::Invalid);
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        }
        self.verify_labels(workspace, retaining, admission)?;
        self.first = None;
        Ok(())
    }

    pub(super) fn verify_labels_ordinary_v1(workspace: &Path)
        -> Result<(), GuestRootMarkerErrorV1>
    {
        Self::new().verify_labels(workspace, false, None)
    }

    fn verify_labels(&mut self, workspace: &Path, retaining: bool,
        admission: Option<&mut dyn FnMut(crate::guest_root_label::GuestRootLabelReadReachedDataV2) -> bool>)
        -> Result<(), GuestRootMarkerErrorV1>
    {
        self.first = Some(Failure::Root);
        self.root = Some(rustix::fs::open(workspace,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()));
        let Some(Ok(root)) = self.root.as_ref() else {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        };
        self.first = Some(Failure::Labels);
        if let Some(original) = self.retained_labels.as_mut() {
            self.retained_label_result = Some(match admission {
                Some(admit) => original.verify_receiving_before_once_v2(root.as_fd(), &mut || true, &mut |shape| admit(shape)),
                None => original.verify_once_v1(root.as_fd()),
            });
        } else {
            self.labels = Some(verify_copied_guest_executable_labels_fd_v1(root.as_fd()));
        }
        if !retaining {
            // The old verify_payload_labels helper closed this descriptor
            // before returning its Result to the marker reader.
            drop(self.root.take());
        }
        if !(matches!(self.labels, Some(Ok(()))) || matches!(self.retained_label_result, Some(Ok(())))) {
            return Err(GuestRootMarkerErrorV1::InvalidPublication);
        }
        Ok(())
    }

}

impl Default for GuestRootMarkerReadOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn expected_proof() -> GuestRootPublicationProofV1 {
        GuestRootPublicationProofV1 {
            sandbox: [1; 16],
            incarnation: [2; 16],
            assignment_epoch: 1,
            assignment_digest: [3; 32],
            creation_operation: [4; 16],
            workspace_handle: [5; 32],
            dataset_guid: 1,
            root_image_digest: [6; 32],
            package_binding: [7; 32],
            root_tree_digest: [8; 32],
            feature_mask: 0,
        }
    }

    #[test]
    fn refused_native_directory_keeps_the_same_first_error_on_retry() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent");
        let mut original = GuestRootMarkerReadOriginalV1::new();

        assert!(original.read_once_v1(directory.path(), &missing, expected_proof()).is_err());
        let actual = original.directory.as_ref().unwrap().as_ref().unwrap_err();
        let actual_address = actual as *const std::io::Error;
        assert_eq!(actual.kind(), std::io::ErrorKind::NotFound);
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(),
            actual_address,
        ));

        assert!(original.read_once_v1(directory.path(), &missing, expected_proof()).is_err());
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(),
            actual_address,
        ));
    }

    #[test]
    fn ordinary_adapter_preserves_native_io_class() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent");

        let error = read_guest_root_marker_v1(directory.path(), &missing, expected_proof()).unwrap_err();

        assert!(matches!(error, GuestRootMarkerErrorV1::Io(cause)
            if cause.kind() == std::io::ErrorKind::NotFound));
    }
}
