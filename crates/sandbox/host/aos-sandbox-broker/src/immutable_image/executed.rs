//! Holds the native executed-file and loader-metadata comparison destinations.
//!
//! These are bounded mechanical originals. They cannot establish a process
//! role, launch, payer or effect; the real purpose keeps its same file/pidfd.

use super::*;
use std::error::Error;

macro_rules! executed_step_v1 {
    (Ordinary, open $original:ident, $executable:ident, $pid:ident) => {
        let $executable = File::open(format!("/proc/{}/exe", $pid))
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
    };
    (Retained, open $original:ident, $executable:ident, $pid:ident) => {
        $original.path = Some(format!("/proc/{}/exe", $pid));
        $original.opened = Some(File::open($original.path.as_ref()
            .ok_or(ImmutableImageErrorV1::Unavailable)?));
        let $executable = $original.opened.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ImmutableImageErrorV1::Unavailable)?;
    };
    (Ordinary, identity $original:ident, $executable:ident) => {
        identity(&$executable.metadata().map_err(|_| ImmutableImageErrorV1::Unavailable)?)
    };
    (Retained, identity $original:ident, $executable:ident) => {{
        $original.metadata = Some($executable.metadata());
        identity($original.metadata.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ImmutableImageErrorV1::Unavailable)?)
    }};
}

macro_rules! executed_recipe_v1 {
    ($mode:ident, $file:ident, $pid:ident, $original:ident) => {{
        executed_step_v1!($mode, open $original, executable, $pid);
        if executed_step_v1!($mode, identity $original, executable) != $file.identity {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        Ok(())
    }};
}

pub(super) use executed_recipe_v1;
// Macro expansion occurs in the immutable parent containing the same kernels.
pub(super) use executed_step_v1;

/// Holds one native executed-file comparison through its actual disposition.
#[must_use = "retain failed native file and result with its original purpose"]
pub struct ImmutableExecutedFileOriginalV1 {
    pub(super) path: Option<String>,
    pub(super) opened: Option<std::io::Result<File>>,
    pub(super) metadata: Option<std::io::Result<Metadata>>,
    pub(super) returned: Option<Result<(), ImmutableImageErrorV1>>,
    pub(super) reentry: Option<ImmutableImageErrorV1>,
    pub(super) entered: bool,
}

impl ImmutableExecutedFileOriginalV1 {
    /// Creates inert native/result destinations without process or file IO.
    #[must_use]
    pub const fn new() -> Self {
        Self { path: None, opened: None, metadata: None, returned: None, reentry: None, entered: false }
    }

    /// Drops only the completed positive probe, preserving the one-shot fence.
    ///
    /// The actual measured immutable file and original pidfd remain owned by
    /// the enclosing purpose. A failed or unentered prefix is untouched.
    pub fn retire_positive_probe_once_v1(&mut self) {
        if matches!(self.returned, Some(Ok(()))) && self.reentry.is_none() {
            drop(self.opened.take());
            drop(self.metadata.take());
            drop(self.path.take());
        }
    }

    /// Borrows the first actual native or semantic refusal without IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.opened).or_else(|| failure(&self.metadata))
            .or_else(|| failure(&self.returned)).or_else(|| self.reentry.as_ref().map(|value| value as _))
    }
}

impl Default for ImmutableExecutedFileOriginalV1 { fn default() -> Self { Self::new() } }

/// Holds the original loader metadata and same canonical map comparison.
#[must_use = "retain failed metadata with the real loader and purpose"]
pub struct ImmutableLoaderMapOriginalV1 {
    pub(super) metadata: Option<std::io::Result<Metadata>>,
    pub(super) returned: Option<Result<bool, ImmutableImageErrorV1>>,
    pub(super) reentry: Option<ImmutableImageErrorV1>,
    pub(super) entered: bool,
}

impl ImmutableLoaderMapOriginalV1 {
    /// Creates inert native/result destinations without a map or file factory.
    #[must_use]
    pub const fn new() -> Self {
        Self { metadata: None, returned: None, reentry: None, entered: false }
    }

    /// Borrows the actual first native metadata or comparison refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.metadata).or_else(|| failure(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|value| value as _))
    }
}

impl Default for ImmutableLoaderMapOriginalV1 { fn default() -> Self { Self::new() } }

pub(super) fn project_unit(value: &Option<Result<(), ImmutableImageErrorV1>>)
    -> Result<(), ImmutableImageErrorV1>
{
    match value {
        Some(Ok(())) => Ok(()),
        Some(Err(ImmutableImageErrorV1::Provisioning)) => Err(ImmutableImageErrorV1::Provisioning),
        _ => Err(ImmutableImageErrorV1::Unavailable),
    }
}

fn failure<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actual_executable() -> RetainedImmutableFileV1 {
        let file = File::open("/proc/self/exe").unwrap();
        let measured = identity(&file.metadata().unwrap());
        // This fixture exercises only the inode comparison mechanism. It has
        // no selected role, pin digest, launch, payer or custody admission.
        RetainedImmutableFileV1 {
            file, path: PathBuf::from("/proc/self/exe"), digest: [0; 32],
            identity: measured, maximum_bytes: MAXIMUM_IMAGE_BYTES, executable: true,
            exact_data_bytes: None,
        }
    }

    #[test]
    fn failed_executed_open_keeps_raw_cause_across_reentry() {
        let measured = actual_executable();
        let mut original = ImmutableExecutedFileOriginalV1::new();
        assert!(measured.require_executed_retaining_v1(u32::MAX, &mut original).is_err());
        assert!(original.metadata.is_none());
        let native = original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(native.kind(), std::io::ErrorKind::NotFound);
        let pointer = std::ptr::from_ref(native);

        assert!(measured.require_executed_retaining_v1(std::process::id(), &mut original).is_err());
        original.retire_positive_probe_once_v1();

        assert_eq!(std::ptr::from_ref(original.failure().unwrap()
            .downcast_ref::<std::io::Error>().unwrap()), pointer);
        assert!(original.opened.as_ref().unwrap().is_err());
        assert!(original.metadata.is_none());
    }

    #[test]
    fn completed_executed_probe_retires_only_its_positive_descriptor() {
        let measured = actual_executable();
        let mut original = ImmutableExecutedFileOriginalV1::new();
        measured.require_executed_retaining_v1(std::process::id(), &mut original).unwrap();
        assert!(original.opened.as_ref().unwrap().is_ok());
        assert!(original.metadata.as_ref().unwrap().is_ok());

        original.retire_positive_probe_once_v1();

        assert!(original.opened.is_none());
        assert!(original.metadata.is_none());
        assert!(matches!(original.returned, Some(Ok(()))));
        assert_eq!(identity(&measured.file.metadata().unwrap()), measured.identity);
        assert!(measured.require_executed_retaining_v1(std::process::id(), &mut original).is_err());
        assert!(original.opened.is_none());
    }
}
