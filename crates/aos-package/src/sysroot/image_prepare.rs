//! Authenticated candidate preparation without boot selection or rollout.
//!
//! Preparation resolves a signed sysroot package and delegates physical staging
//! and durable image indexing to the existing image-stage implementation. The
//! returned generation is its exact admitted receipt; no operator-source request
//! or next-boot selection is generated here.

use anyhow::{Context as _, Result, ensure};
use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::environment::RuntimeRequirement;
use crate::profile::Profile;
use crate::registry::RegistrySet;
use crate::resolve::{ResolvedClosure, resolve_multiple};
use crate::types::{ImageGeneration, ProfileScope};
use crate::{AbilityCancellationGuard, ImageCommand, PackageCommand};

/// Selects the checks applied before candidate image staging.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ImagePreparationPurpose {
    /// Prepares an image without granting any subsequent selection authority.
    #[default]
    Ordinary,
    /// Also requires explicit authenticated candidate health for later rollout.
    Qualified,
}

/// Supplies package selection and operator consent for candidate preparation.
#[derive(Clone, Debug)]
pub struct ImagePrepareOptions {
    /// Names the sysroot package resolved from signed registry metadata.
    pub package: String,
    /// Restricts resolution to this configured registry when supplied.
    pub registry: Option<String>,
    /// Selects ordinary staging or the additional candidate health requirement.
    pub purpose: ImagePreparationPurpose,
    /// Previews resolution without importing, staging, or writing image state.
    pub dry_run: bool,
    /// Bypasses the confirmation prompt when explicitly authorized by the caller.
    pub yes: bool,
}

/// Authenticates and stages one candidate without choosing the next boot.
///
/// Returns the exact indexed [`ImageGeneration`], or `None` for a dry-run
/// preview. Qualified preparation does not qualify or submit a rollout: later
/// operator-source selection still performs its own authorization and checks.
/// Cancellation during immutable transfers is honored after those transfers
/// finish and before physical staging. Physical helper processes support bounded
/// cancellation; interrupted staging retains its intent for authenticated retry.
///
/// # Errors
/// Returns an error outside a writable live AOS system context or root scope,
/// for profile contention, pending image work, failed signed resolution,
/// rejected operator consent, cancelled work, or failed authenticated staging.
pub async fn prepare_image(
    config: &ApmConfig,
    options: &ImagePrepareOptions,
    printer: &Printer,
) -> Result<Option<ImageGeneration>> {
    let qualified = options.purpose == ImagePreparationPurpose::Qualified;
    crate::runtime_boundary::validate(&PackageCommand::Image {
        command: ImageCommand::Prepare {
            package: options.package.clone(),
            registry: options.registry.clone(),
            qualified,
        },
    })?;
    ensure!(
        config.scope == ProfileScope::System,
        "image preparation requires system scope"
    );
    RuntimeRequirement::LiveAos.validate()?;
    ensure!(
        rustix::process::geteuid().as_raw() == 0,
        "image preparation requires root privileges"
    );

    let profile = Profile::open_readonly(ProfileScope::System);
    let mutation = if options.dry_run {
        None
    } else {
        Some(profile.lock_mutation()?)
    };
    ensure!(
        !crate::profile::deployment::has_pending_deployment(&profile.path)?,
        "profile activation is still pending"
    );
    let state =
        super::load_image_generation_state_pub(std::path::Path::new(super::IMAGE_PROFILE_DIR))?;
    super::image_stage::ensure_staging_available(&state)?;
    let (registries, closure) =
        resolve_candidate(config, &options.package, options.registry.as_deref())?;
    printer.info(&format!(
        "Prepare system image {} {}",
        closure.root.name, closure.root.version
    ));
    if options.dry_run {
        printer.info(
            "Dry run -- immutable imports, physical staging, and image indexing have not run.",
        );
        return Ok(None);
    }
    if !options.yes && !config.settings.assume_yes {
        crate::install::confirm(printer)?;
    }

    // Staging serializes physical writes with its candidate lock. Admitted
    // inactive-slot retirement acquires the profile lock independently.
    drop(mutation);

    let cancellation = AbilityCancellationGuard::install()?;
    let epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let created_at = crate::install::chrono_iso8601(epoch.as_secs().try_into()?);
    let candidate = super::image_stage::stage_candidate(
        config,
        &registries,
        &closure,
        &created_at,
        qualified,
        cancellation.token(),
        printer,
    )
    .await?;
    Ok(Some(candidate))
}

pub(super) fn resolve_candidate(
    config: &ApmConfig,
    package: &str,
    registry: Option<&str>,
) -> Result<(RegistrySet, ResolvedClosure)> {
    let registries = crate::install::load_registries(config)?;
    let closure = resolve_multiple(&registries, &[package.to_owned()], registry)?
        .into_iter()
        .find(|closure| closure.root.name == package)
        .with_context(|| format!("package '{package}' not found"))?;
    ensure!(
        closure.root.sysroot,
        "package '{package}' is not a sysroot package (missing sysroot = true)"
    );
    Ok((registries, closure))
}
