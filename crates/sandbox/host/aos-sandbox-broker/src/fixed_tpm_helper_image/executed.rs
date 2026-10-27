//! Keeps the actual initial helper executable/map prefix through disposition.
//!
//! One completed positive comparison retires its two fresh proc probe files.
//! Failed native prefixes stay owned; immutable image files and the original
//! pidfd remain the actual identity anchors throughout later effects.

use super::*;
use crate::immutable_image::{ImmutableExecutedFileOriginalV1, ImmutableLoaderMapOriginalV1};
use std::error::Error;

macro_rules! helper_executed_step_v1 {
    (Ordinary, executable $image:ident, $pid:ident, $original:ident) => {
        $image.executable.require_executed($pid)?;
    };
    (Retained, executable $image:ident, $pid:ident, $original:ident) => {
        $image
            .executable
            .require_executed_retaining_v1($pid, &mut $original.executable)?;
    };
    (Ordinary, maps $pid:ident, $original:ident, $maps:ident) => {
        let mut $maps = String::new();
        File::open(format!("/proc/{}/maps", $pid))
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?
            .take(MAXIMUM_MAPS_BYTES + 1)
            .read_to_string(&mut $maps)
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
    };
    (Retained, maps $pid:ident, $original:ident, $maps:ident) => {
        $original.path = Some(format!("/proc/{}/maps", $pid));
        $original.opened = Some(File::open(
            $original
                .path
                .as_ref()
                .ok_or(ImmutableImageErrorV1::Unavailable)?,
        ));
        let file = $original
            .opened
            .as_mut()
            .and_then(|value| value.as_mut().ok())
            .ok_or(ImmutableImageErrorV1::Unavailable)?;
        $original.read = Some(
            file.by_ref()
                .take(MAXIMUM_MAPS_BYTES + 1)
                .read_to_string(&mut $original.maps),
        );
        if !matches!($original.read, Some(Ok(_))) {
            return Err(ImmutableImageErrorV1::Unavailable);
        }
        let $maps = &$original.maps;
    };
    (Ordinary, loader $image:ident, $maps:ident, $original:ident) => {
        $image.loader.mapped_in_helper_data_v5(&$maps)?
    };
    (Retained, loader $image:ident, $maps:ident, $original:ident) => {
        $image
            .loader
            .mapped_in_helper_retaining_v1($maps, &mut $original.loader)?
    };
}

macro_rules! helper_executed_recipe_v1 {
    ($mode:ident, $image:ident, $pid:ident, $original:ident) => {{
        helper_executed_step_v1!($mode, executable $image, $pid, $original);
        helper_executed_step_v1!($mode, maps $pid, $original, maps);
        if maps.len() as u64 > MAXIMUM_MAPS_BYTES {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        let mapped = helper_executed_step_v1!($mode, loader $image, maps, $original);
        if !mapped {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        Ok(())
    }};
}

pub(super) use {helper_executed_recipe_v1, helper_executed_step_v1};

/// Retains actual native executed-image observations without authority.
#[must_use = "retain reached native results through purpose disposition"]
pub struct HelperExecutedImageOriginalV1 {
    pub(super) executable: ImmutableExecutedFileOriginalV1,
    pub(super) path: Option<String>,
    pub(super) opened: Option<std::io::Result<File>>,
    pub(super) maps: String,
    pub(super) read: Option<std::io::Result<usize>>,
    pub(super) loader: ImmutableLoaderMapOriginalV1,
    pub(super) returned: Option<Result<(), ImmutableImageErrorV1>>,
    pub(super) reentry: Option<ImmutableImageErrorV1>,
}

impl HelperExecutedImageOriginalV1 {
    /// Creates inert destinations without native IO.
    pub fn new() -> Self {
        Self {
            executable: ImmutableExecutedFileOriginalV1::new(),
            path: None,
            opened: None,
            maps: String::new(),
            read: None,
            loader: ImmutableLoaderMapOriginalV1::new(),
            returned: None,
            reentry: None,
        }
    }

    /// Supplies retained native probe and bounded map backing before IO.
    pub fn receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                usize::try_from(MAXIMUM_MAPS_BYTES.checked_add(1)?)
                    .ok()?
                    .checked_mul(2)?,
            )?
            .checked_add(4096)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, 2),
        )
    }

    /// Retires only positive proc probes after the entire comparison succeeds.
    pub fn retire_positive_probes_once_v1(&mut self) {
        if matches!(self.returned, Some(Ok(()))) && self.reentry.is_none() {
            self.executable.retire_positive_probe_once_v1();
            drop(self.opened.take());
            drop(self.path.take());
            drop(std::mem::take(&mut self.maps));
        }
    }

    /// Adds the same native maps reader's bounded input and trailing byte.
    pub fn receiving_with_input_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        Some(Self::receiving_demand_v1()?.with(
            aos_sandbox_model::ResourceDimension::OutputBytes,
            MAXIMUM_MAPS_BYTES.checked_add(1)?,
        ))
    }

    /// Borrows the earliest reached native or typed comparison cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.executable
            .failure()
            .or_else(|| error(&self.opened))
            .or_else(|| error(&self.read))
            .or_else(|| self.loader.failure())
            .or_else(|| error(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|value| value as _))
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl Default for HelperExecutedImageOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}
