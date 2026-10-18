//! Strict source-foundation v1 metadata and optional source-only enrichments.
//!
//! Platform, terminal and native-origin metadata bind retained source bytes.
//! They do not qualify full-system execution or replace closed-profile witnesses.

use std::path::{Component, Path, PathBuf};

use super::{Artifact, NodeObservedError, U64, refused};
use serde::{Deserialize, Deserializer};

#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Source {
    schema: String,
    revision: String,
    upstream: String,
    version: String,
    build_configuration: String,
    pub(super) recipe_sha256: String,
    pub(super) patches: Vec<RecipePatch>,
    crucible_node_protocol: bool,
    qualified_exact_capture: bool,
    qualified_live_branch: bool,
    // The original v1 producer has no extensions. Each later producer adds
    // explicit source bindings without changing that base schema or authority.
    #[serde(default, deserialize_with = "present_value")]
    full_system_qualified: Option<bool>,
    #[serde(default, deserialize_with = "present_value")]
    platform_recipe_sha256: Option<String>,
    #[serde(default, deserialize_with = "present_value")]
    platform_manifest_helper_sha256: Option<String>,
    #[serde(default, deserialize_with = "present_value")]
    terminal_source: Option<TerminalSource>,
    #[serde(default, deserialize_with = "present_value")]
    native_compiler_origin: Option<NativeCompilerOrigin>,
}

impl Source {
    pub(super) fn validate(&self) -> Result<(), NodeObservedError> {
        if self.schema != "crucible.gem5.source-foundation.v1"
            || self.revision != "f5c5a6e390f55dd5984977815bf9d0bd05da6945"
            || self.upstream != "https://github.com/gem5/gem5"
            || self.version != "25.1.0.1"
            || self.build_configuration != "ALL"
            || self.patches.is_empty()
            || self.crucible_node_protocol
            || self.qualified_exact_capture
            || self.qualified_live_branch
            || self.full_system_qualified == Some(true)
            || !valid_digest(&self.recipe_sha256)
        {
            return Err(refused("source-built gem5 implementation closure differs"));
        }
        for patch in &self.patches {
            patch.validate()?;
        }

        match (
            &self.platform_recipe_sha256,
            &self.platform_manifest_helper_sha256,
        ) {
            (None, None) => {}
            (Some(recipe), Some(helper))
                if valid_digest(recipe)
                    && valid_digest(helper)
                    && self.full_system_qualified == Some(false) => {}
            _ => return Err(refused("gem5 platform source binding is incomplete")),
        }
        if let Some(terminal) = &self.terminal_source {
            if self.full_system_qualified != Some(false) {
                return Err(refused("gem5 terminal source scope is absent"));
            }
            terminal.validate(&self.patches)?;
        }
        if let Some(origin) = &self.native_compiler_origin {
            origin.validate()?;
        }
        Ok(())
    }

    pub(super) fn measure_extensions(&self, native: &Artifact) -> Result<(), NodeObservedError> {
        let root = native
            .path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| refused("installed gem5 native package root is absent"))?
            .join("share/gem5");
        if let (Some(recipe), Some(helper)) = (
            &self.platform_recipe_sha256,
            &self.platform_manifest_helper_sha256,
        ) {
            measure_recipe(root.join("platform-source/recipe.nix"), recipe)?;
            measure_recipe(root.join("platform-source/manifest-helper.py"), helper)?;
        }
        if let Some(terminal) = &self.terminal_source {
            measure_recipe(
                root.join("terminal-source/recipe.nix"),
                &terminal.recipe_sha256,
            )?;
            measure_recipe(
                root.join("terminal-source/manifest-helper.py"),
                &terminal.manifest_helper_sha256,
            )?;
        }
        if let Some(origin) = &self.native_compiler_origin {
            // The wrapper preserves the original ELF. Its measured origin is
            // provenance only; none of these fields supplies node authority.
            if origin.native_elf.bytes != native.length.get()
                || origin.native_elf.sha256 != native.sha256
            {
                return Err(refused("gem5 native producer ELF binding differs"));
            }
            origin.origin.measure(root.join("native-origin.json"))?;
            origin
                .native_elf
                .measure(origin.native_output.join("bin/gem5"))?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecipePatch {
    pub(super) file: String,
    pub(super) sha256: String,
}

impl RecipePatch {
    fn validate(&self) -> Result<(), NodeObservedError> {
        super::schema::require_filename(&self.file)?;
        if !valid_digest(&self.sha256) {
            return Err(refused("gem5 source patch digest is invalid"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalSource {
    recipe_sha256: String,
    manifest_helper_sha256: String,
    patches: Vec<RecipePatch>,
    full_system_qualified: bool,
}

impl TerminalSource {
    fn validate(&self, source_patches: &[RecipePatch]) -> Result<(), NodeObservedError> {
        if self.full_system_qualified
            || !valid_digest(&self.recipe_sha256)
            || !valid_digest(&self.manifest_helper_sha256)
            || self.patches.is_empty()
        {
            return Err(refused("gem5 terminal source binding differs"));
        }
        for patch in &self.patches {
            patch.validate()?;
            if !source_patches
                .iter()
                .any(|source| source.file == patch.file && source.sha256 == patch.sha256)
            {
                return Err(refused("gem5 terminal patch is absent from source closure"));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCompilerOrigin {
    schema: String,
    native_output: PathBuf,
    native_source: PathBuf,
    native_derivation: PathBuf,
    native_elf: SourceMeasurement,
    origin: SourceMeasurement,
}

impl NativeCompilerOrigin {
    fn validate(&self) -> Result<(), NodeObservedError> {
        if self.schema != "crucible.gem5.native-wrapper-origin.v1"
            || !store_root(&self.native_output)
            || !store_root(&self.native_source)
            || !store_root(&self.native_derivation)
            || self
                .native_derivation
                .extension()
                .is_none_or(|value| value != "drv")
        {
            return Err(refused("gem5 native producer source binding differs"));
        }
        self.native_elf.validate()?;
        self.origin.validate()?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMeasurement {
    // The source-owned Python emitter uses JSON integers, not CNP U64 strings.
    bytes: u64,
    sha256: String,
}

impl SourceMeasurement {
    fn validate(&self) -> Result<(), NodeObservedError> {
        if self.bytes == 0 || self.bytes > super::MAX_ARTIFACT_BYTES || !valid_digest(&self.sha256)
        {
            return Err(refused("gem5 native source measurement is invalid"));
        }
        Ok(())
    }

    fn measure(&self, path: PathBuf) -> Result<(), NodeObservedError> {
        Artifact {
            path,
            sha256: self.sha256.clone(),
            length: U64::new(self.bytes),
        }
        .measure()?;
        Ok(())
    }
}

fn store_root(path: &Path) -> bool {
    path.starts_with("/nix/store")
        && path.components().count() == 4
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn valid_digest(value: &str) -> bool {
    super::schema::valid_digest(value)
}

fn measure_recipe(path: PathBuf, sha256: &str) -> Result<(), NodeObservedError> {
    super::schema::measure_recipe(path, sha256)
}

// Only a genuinely absent field uses serde's default. A present extension must
// decode as its nonnullable source-owned type; explicit null is not omission.
fn present_value<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
