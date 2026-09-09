//! Offline reconstruction and rendering of checked ability plans.

use std::fs::File;
use std::io::{Read as _, Take};

use anyhow::{Context as _, Result, bail};
use aos_ability_inspect::{
    INSPECTION_BUNDLE_MAX_BYTES, InspectionBundle, InspectionView, ProjectionKind, RenderFormat,
    ViewAnchor, render, render_projection,
};
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};

use crate::cli::{AbilityCommand, AbilityInspectArgs, AbilityProjection, AbilityRenderFormat};

/// Runs one offline ability inspection command.
///
/// # Errors
///
/// Returns an error if the input cannot be read within its bound, its canonical
/// bundle or external digest is invalid, semantic revalidation fails, or the
/// checked view cannot be rendered.
pub fn run(command: &AbilityCommand, printer: &Printer) -> Result<()> {
    match command {
        AbilityCommand::Inspect(args) => inspect(args, printer),
    }
}

fn inspect(args: &AbilityInspectArgs, printer: &Printer) -> Result<()> {
    let bytes = read_bounded_bundle(args)?;
    let expected_digest = args
        .expected_digest
        .as_deref()
        .map(Sha256Digest::parse)
        .transpose()
        .context("parsing --expected-digest")?;
    let checked = InspectionBundle::decode(&bytes)
        .context("decoding canonical ability inspection bundle")?
        .check(expected_digest)
        .context("checking ability inspection bundle semantics")?;
    let view = InspectionView::from_bundle(&checked)
        .context("projecting checked ability inspection view")?;

    let format = args.format.map(Into::into).unwrap_or_else(|| {
        if printer.mode() == OutputMode::Json {
            RenderFormat::Json
        } else {
            RenderFormat::Text
        }
    });
    let output = match args.projection {
        Some(projection) => {
            let projection = view
                .project(projection.into())
                .context("projecting semantic ability graph")?;
            render_projection(&projection, format)
                .context("rendering projected ability inspection view")?
        }
        None => render(&view, format).context("rendering checked ability inspection view")?,
    };
    printer.raw(&output);

    if matches!(view.anchor(), ViewAnchor::UnanchoredBundle { .. }) {
        printer.warning(
            "the bundle was semantically checked without an independent digest; its captured environment and policy are not asserted current",
        );
    }
    Ok(())
}

fn read_bounded_bundle(args: &AbilityInspectArgs) -> Result<Vec<u8>> {
    let file = File::open(&args.bundle)
        .with_context(|| format!("opening inspection bundle {}", args.bundle.display()))?;
    let limit = u64::try_from(INSPECTION_BUNDLE_MAX_BYTES)
        .context("inspection bundle byte limit does not fit this platform")?;
    let mut reader: Take<File> = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading inspection bundle {}", args.bundle.display()))?;
    if bytes.len() > INSPECTION_BUNDLE_MAX_BYTES {
        bail!(
            "inspection bundle {} exceeds the {} byte limit",
            args.bundle.display(),
            INSPECTION_BUNDLE_MAX_BYTES
        );
    }
    Ok(bytes)
}

impl From<AbilityRenderFormat> for RenderFormat {
    fn from(value: AbilityRenderFormat) -> Self {
        match value {
            AbilityRenderFormat::Text => Self::Text,
            AbilityRenderFormat::Json => Self::Json,
            AbilityRenderFormat::Dot => Self::Dot,
            AbilityRenderFormat::Mermaid => Self::Mermaid,
        }
    }
}

impl From<AbilityProjection> for ProjectionKind {
    fn from(value: AbilityProjection) -> Self {
        match value {
            AbilityProjection::Composition => Self::Composition,
            AbilityProjection::BindingAuthority => Self::BindingAuthority,
            AbilityProjection::Activation => Self::Activation,
            AbilityProjection::Retention => Self::Retention,
        }
    }
}
