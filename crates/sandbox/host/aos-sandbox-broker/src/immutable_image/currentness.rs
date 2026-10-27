//! Owns one same-file immutable revalidation at the actual shared native calls.
//!
//! The caller retains its already-measured file and independently pays this
//! passive destination. It supplies no pathname, file descriptor, selected
//! image, authority, account or callback to this one-shot observation.

use std::error::Error;
use std::ops::Deref;

use super::*;

pub(super) struct NamesOriginalV1 {
    pub(super) held: Option<std::io::Result<Metadata>>,
    pub(super) named: Option<std::io::Result<Metadata>>,
    pub(super) mount: Option<Result<rustix::fs::StatVfs, rustix::io::Errno>>,
    pub(super) binding: Option<Result<(), ImmutableImageErrorV1>>,
}

impl NamesOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            held: None,
            named: None,
            mount: None,
            binding: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.held)
            .or_else(|| failure(&self.named))
            .or_else(|| failure(&self.mount))
            .or_else(|| failure(&self.binding))
    }
}

/// Retains original native and typed results of one immutable comparison.
#[must_use = "retain actual failed native observations with their same measured file"]
pub struct ImmutableFileRevalidationOriginalV1 {
    names: [NamesOriginalV1; 2],
    digest: Option<Result<[u8; 32], ImmutableImageErrorV1>>,
    digest_binding: Option<Result<(), ImmutableImageErrorV1>>,
    observation: ImmutableFileObservationV1,
    result: Option<Result<(), ImmutableImageErrorV1>>,
    entered: bool,
}

impl ImmutableFileRevalidationOriginalV1 {
    /// Creates inert native-result destinations without acquisition or authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            names: [NamesOriginalV1::new(), NamesOriginalV1::new()],
            digest: None,
            digest_binding: None,
            observation: ImmutableFileObservationV1::default(),
            result: None,
            entered: false,
        }
    }

    /// Describes the actual result owners and bounded same-file digest work.
    ///
    /// This DATA requires genuine caller admission before native observation.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        // The retained scratch and possible ordinary stack scratch coexist in
        // the shared hash engine. No full configured image copy is allocated.
        let bytes = std::mem::size_of::<Self>()
            .checked_add(8192)?
            .checked_add(2 * std::mem::size_of::<Sha256>())?
            .checked_add(8 * 256)?;
        Some(ResourceVector::ZERO
            // Native result destinations and controls are compiled memory,
            // rather than resident namespace entries.
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Borrows the earliest actual native or typed refusal from this pass.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.names[0].failure()
            .or_else(|| match self.observation.first.as_ref()? {
                ImmutableFileNativeCauseV1::Io(error) => Some(error as &dyn Error),
                ImmutableFileNativeCauseV1::Errno(error) => Some(error as &dyn Error),
            })
            .or_else(|| failure(&self.digest))
            .or_else(|| failure(&self.digest_binding))
            .or_else(|| self.names[1].failure())
            .or_else(|| failure(&self.result))
    }

    // An incomplete acquisition has no measured digest/name conjunction to
    // revalidate. Observe only its actual held descriptor and retain the raw
    // result; even a successful metadata read remains an incomplete comparison.
    pub(super) fn observe_held_metadata_only_v1(
        &mut self,
        file: &File,
    ) -> Result<(), ImmutableImageErrorV1> {
        if self.entered { return Err(ImmutableImageErrorV1::Provisioning); }
        self.entered = true;
        self.names[0].held = Some(file.metadata());
        self.result = Some(Err(if matches!(self.names[0].held, Some(Ok(_))) {
            ImmutableImageErrorV1::Provisioning
        } else {
            ImmutableImageErrorV1::Unavailable
        }));
        unit(&self.result)
    }

    /// Reports a completed comparison without granting currentness or reuse.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.result, Some(Ok(())))
    }
}

impl Default for ImmutableFileRevalidationOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl RetainedImmutableFileV1 {
    /// Revalidates this same measured file into a prearmed passive destination.
    ///
    /// All original before/after metadata and mount results, digest/native
    /// failure and typed comparisons remain resident on refusal. Reentry does
    /// not start another pass or replace the original cause.
    ///
    /// # Errors
    /// Rejects repeated entry, unavailable native reads or changed original
    /// names, safe metadata, mounts, length or bytes.
    pub fn revalidate_retaining(
        &self,
        original: &mut ImmutableFileRevalidationOriginalV1,
    ) -> Result<(), ImmutableImageErrorV1> {
        if original.entered {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        original.entered = true;
        let result = self.revalidate_recipe(
            &mut Some(&mut original.observation),
            Some(CurrentnessSlotsV1 {
                names: &mut original.names,
                digest: &mut original.digest,
                digest_binding: &mut original.digest_binding,
            }),
        );
        original.result = Some(result);
        unit(&original.result)
    }
}

pub(super) struct CurrentnessSlotsV1<'original> {
    pub(super) names: &'original mut [NamesOriginalV1; 2],
    pub(super) digest: &'original mut Option<Result<[u8; 32], ImmutableImageErrorV1>>,
    pub(super) digest_binding: &'original mut Option<Result<(), ImmutableImageErrorV1>>,
}

pub(super) enum NativeOutputV1<'original, T> {
    Local(T),
    Original(&'original T),
}

impl<T> Deref for NativeOutputV1<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        match self {
            Self::Local(value) => value,
            Self::Original(value) => value,
        }
    }
}

pub(super) fn observe_io_original<'original, T>(
    result: std::io::Result<T>,
    observation: &mut Option<&mut ImmutableFileObservationV1>,
    original: Option<&'original mut Option<std::io::Result<T>>>,
) -> Result<NativeOutputV1<'original, T>, ImmutableImageErrorV1> {
    match original {
        Some(original) => {
            *original = Some(result);
            match original.as_ref() {
                Some(Ok(value)) => Ok(NativeOutputV1::Original(value)),
                _ => Err(ImmutableImageErrorV1::Unavailable),
            }
        }
        None => observe_io(result, observation, false).map(NativeOutputV1::Local),
    }
}

pub(super) fn observe_native_original<'original, T>(
    result: Result<T, rustix::io::Errno>,
    observation: &mut Option<&mut ImmutableFileObservationV1>,
    original: Option<&'original mut Option<Result<T, rustix::io::Errno>>>,
) -> Result<NativeOutputV1<'original, T>, ImmutableImageErrorV1> {
    match original {
        Some(original) => {
            *original = Some(result);
            match original.as_ref() {
                Some(Ok(value)) => Ok(NativeOutputV1::Original(value)),
                _ => Err(ImmutableImageErrorV1::Unavailable),
            }
        }
        None => observe_native(result, observation).map(NativeOutputV1::Local),
    }
}

pub(super) fn projection(error: &ImmutableImageErrorV1) -> ImmutableImageErrorV1 {
    match error {
        ImmutableImageErrorV1::Unavailable => ImmutableImageErrorV1::Unavailable,
        ImmutableImageErrorV1::Provisioning => ImmutableImageErrorV1::Provisioning,
    }
}

pub(super) fn unit(
    result: &Option<Result<(), ImmutableImageErrorV1>>,
) -> Result<(), ImmutableImageErrorV1> {
    match result {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => Err(projection(error)),
        None => Err(ImmutableImageErrorV1::Unavailable),
    }
}

fn failure<T, E: Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err())
        .map(|error| error as &dyn Error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_current_name_keeps_original_native_error_after_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("measured-file");
        std::fs::write(&path, b"original").unwrap();
        let file = File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        // Measurement DATA fixture only. This negative path fails on the
        // actual missing name before any metadata policy or digest admission.
        let measured = RetainedImmutableFileV1 {
            file,
            path: path.clone(),
            digest: [0; 32],
            identity: identity(&metadata),
            maximum_bytes: MAXIMUM_IMAGE_BYTES,
            executable: false,
            exact_data_bytes: None,
        };
        std::fs::remove_file(&path).unwrap();
        let mut original = ImmutableFileRevalidationOriginalV1::new();

        assert!(matches!(
            measured.revalidate_retaining(&mut original),
            Err(ImmutableImageErrorV1::Unavailable),
        ));
        let native = original.names[0].named.as_ref().unwrap().as_ref().unwrap_err();
        assert_eq!(native.kind(), std::io::ErrorKind::NotFound);
        let pointer = native as *const std::io::Error;
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(),
            pointer,
        ));
        assert!(matches!(original.names[0].held, Some(Ok(_))));
        assert!(original.names[0].mount.is_none());
        assert!(original.digest.is_none());
        assert!(original.names[1].held.is_none());

        std::fs::write(&path, b"replacement").unwrap();
        assert!(measured.revalidate_retaining(&mut original).is_err());
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(),
            pointer,
        ));
        assert!(original.names[0].mount.is_none());
        assert!(!original.is_complete());
    }
}

// The real measured file stays on its role owner; these slots retain only
// this same before/read/after pass and grant no independent file admission.
pub(crate) struct ImmutableReadOriginalV1 {
    pub(super) before_original: ImmutableFileRevalidationOriginalV1,
    pub(super) before: Option<Result<(), ImmutableImageErrorV1>>,
    pub(super) bytes: Vec<u8>,
    pub(super) read: Option<std::io::Result<()>>,
    pub(super) after_original: ImmutableFileRevalidationOriginalV1,
    pub(super) after: Option<Result<(), ImmutableImageErrorV1>>,
}

pub(super) struct BoundedReadSlotsV1<'original> {
    pub(super) before_original: &'original mut ImmutableFileRevalidationOriginalV1,
    pub(super) before: &'original mut Option<Result<(), ImmutableImageErrorV1>>,
    pub(super) read: &'original mut Option<std::io::Result<()>>,
    pub(super) after_original: &'original mut ImmutableFileRevalidationOriginalV1,
    pub(super) after: &'original mut Option<Result<(), ImmutableImageErrorV1>>,
}

impl ImmutableReadOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            before_original: ImmutableFileRevalidationOriginalV1::new(),
            before: None,
            bytes: Vec::new(),
            read: None,
            after_original: ImmutableFileRevalidationOriginalV1::new(),
            after: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_original.failure()
            .or_else(|| failure(&self.before))
            .or_else(|| failure(&self.read))
            .or_else(|| self.after_original.failure())
            .or_else(|| failure(&self.after))
    }

    pub(crate) fn requested_bytes_v1(maximum: usize) -> Option<usize> {
        let current = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        let current = usize::try_from(current.get(aos_sandbox_model::ResourceDimension::MemoryBytes)).ok()?;
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(current.checked_mul(2)?)?
            .checked_add(maximum.checked_mul(3)?)
    }
}

#[cfg(test)]
mod bounded_read_tests {
    use super::*;

    #[test]
    fn disappeared_name_preserves_actual_before_error_and_same_held_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unit");
        std::fs::write(&path, b"unit bytes").unwrap();
        let file = File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let measured = RetainedImmutableFileV1 {
            file,
            path: path.clone(),
            digest: [0; 32],
            identity: identity(&metadata),
            maximum_bytes: 64 * 1024,
            executable: false,
            exact_data_bytes: None,
        };
        std::fs::remove_file(&path).unwrap();
        let mut original = ImmutableReadOriginalV1::new();

        assert!(measured.read_bounded_retaining_v1(&mut original).is_err());

        let native = original.before_original.failure().unwrap()
            .downcast_ref::<std::io::Error>().unwrap();
        let pointer = native as *const std::io::Error;
        assert_eq!(native.kind(), std::io::ErrorKind::NotFound);
        assert!(std::ptr::eq(original.failure().unwrap()
            .downcast_ref::<std::io::Error>().unwrap(), pointer));
        assert_eq!(measured.file.metadata().unwrap().len(), 10);
        assert!(original.read.is_none());
        assert!(original.after.is_none());

        assert!(measured.read_bounded_retaining_v1(&mut original).is_err());
        assert!(std::ptr::eq(original.failure().unwrap()
            .downcast_ref::<std::io::Error>().unwrap(), pointer));
    }
}
