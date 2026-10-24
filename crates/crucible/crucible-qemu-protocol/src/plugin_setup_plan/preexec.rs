//! Decodes plan data from the single selected pre-exec carrier edition.
//!
//! ```text
//! CRUCSUP8 | BE schema8/header40/total/A/S/W/Startup128/Purpose2520
//! body: AppRandom | Selectable | optional CRUCWSP2[128] | Startup | CRUCPUR8
//! Purpose tail (big-endian integers):
//! 568..592: child socket device, inode, and SO_COOKIE (u64 each)
//! 592..624: session[32]
//! 624..720: target daemon epoch, owner ID, and node ID (32 bytes each)
//! 720..736: target owner generation and arena generation (u64 each)
//! 736: retained-template boolean; 737..744: zero reserved bytes
//! Entire 568..744 zero: no authenticated RAM endpoint
//! 744..1000: CRUCFAM1, schema1, length256, containing cap/account/assignment
//! 808..1000: two fixed96-byte reservation rows; no execution generations
//! ```
//!
//! This parser authenticates no issuer and issues no purpose. The selected
//! native Source independently retains and authenticates the same sealed role.

use super::*;

mod family;

const HEADER: usize = 40;
const PURPOSE: usize = PROCESS_PURPOSE_BYTES;

pub(super) fn decode_parts(
    bytes: &[u8],
) -> Result<(AppRandomBranchPlan, SelectableCatalogPlan), PluginSetupPlanError> {
    decode_profile(bytes, false)
}

pub(super) fn decode_profile(
    bytes: &[u8],
    publisher: bool,
) -> Result<(AppRandomBranchPlan, SelectableCatalogPlan), PluginSetupPlanError> {
    decode_edition(
        bytes,
        if publisher {
            Edition::Publisher
        } else {
            Edition::Source
        },
    )
}

/// Keeps each selected outer and subscription edition exact before body reads.
pub(super) enum Edition {
    /// Requires the original plan-eight process purpose.
    Source,
    /// Requires plan nine and schema-one publisher purpose.
    Publisher,
    /// Requires plan ten and the separate Quantum-only schema-two purpose.
    Quantum,
    /// Requires plan twelve and its distinct dormant delegation purpose.
    DeferredCleanup,
    /// Requires plan thirteen and the appended immutable runtime-pair record.
    RuntimeArtifact,
    /// Requires plan fourteen and the separate containing-process transfer.
    NativeTransfer,
    /// Requires plan fifteen with complete manifest and paid-probe descriptions.
    NativeProfile,
}

/// Parses the exact requested carrier and its corresponding purpose edition.
///
/// # Errors
/// Refuses mixed editions, malformed framing, mismatched containing identities,
/// oversized sections or invalid nested plans.
pub(super) fn decode_edition(
    bytes: &[u8],
    edition: Edition,
) -> Result<(AppRandomBranchPlan, SelectableCatalogPlan), PluginSetupPlanError> {
    let (magic, version, publisher) = match edition {
        Edition::Source => (b"CRUCSUP8", 8, false),
        Edition::Publisher => (b"CRUCSUP9", 9, true),
        Edition::Quantum => (b"CRUCSU10", 10, true),
        Edition::DeferredCleanup => (b"CRUCSU12", 12, true),
        Edition::RuntimeArtifact => (b"CRUCSU13", 13, true),
        Edition::NativeTransfer => (b"CRUCSU14", 14, true),
        Edition::NativeProfile => (b"CRUCSU15", 15, true),
    };
    let invalid = |section| PluginSetupPlanError::InvalidPreexecSection { section };
    let profile = matches!(edition, Edition::NativeProfile);
    let native = matches!(edition, Edition::NativeTransfer | Edition::NativeProfile);
    let runtime = matches!(
        edition,
        Edition::RuntimeArtifact | Edition::NativeTransfer | Edition::NativeProfile
    );
    let header = if profile {
        80
    } else if native {
        64
    } else if runtime {
        56
    } else if publisher {
        48
    } else {
        HEADER
    };
    let tail = if matches!(
        edition,
        Edition::DeferredCleanup
            | Edition::RuntimeArtifact
            | Edition::NativeTransfer
            | Edition::NativeProfile
    ) {
        crate::deferred_cleanup::DEFERRED_CLEANUP_PURPOSE_BYTES
    } else if publisher {
        crate::publisher_subscription::PUBLISHER_PURPOSE_BYTES
    } else {
        0
    };
    let runtime_len = if runtime {
        crate::runtime_artifact::RUNTIME_ARTIFACT_PAIR_BYTES
    } else {
        0
    };
    let native_len = if native {
        crate::native_transfer::NATIVE_TRANSFER_BYTES
    } else {
        0
    };
    if bytes.len() > PLUGIN_SETUP_PLAN_MAX_BYTES {
        return Err(PluginSetupPlanError::PlanTooLarge {
            bytes: bytes.len(),
            maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
        });
    }
    if bytes.len() < header
        || bytes[..8] != *magic
        || read_u32(bytes, 8)? != version
        || read_u32(bytes, 12)? != header as u32
    {
        return Err(invalid("outer"));
    }
    if publisher && (read_u32(bytes, 40)? as usize != tail || read_u32(bytes, 44)? != 0) {
        return Err(invalid("publisher header"));
    }
    if runtime && (read_u32(bytes, 48)? as usize != runtime_len || read_u32(bytes, 52)? != 0) {
        return Err(invalid("runtime-artifact header"));
    }
    if native && (read_u32(bytes, 56)? as usize != native_len || read_u32(bytes, 60)? != 0) {
        return Err(invalid("native-transfer header"));
    }
    let manifest_len = if profile {
        read_u32(bytes, 64)? as usize
    } else {
        0
    };
    let probe_len = if profile {
        crate::native_transfer::probe::NATIVE_PROBE_REPORT_BYTES
    } else {
        0
    };
    if profile
        && (manifest_len > crate::native_transfer::manifest::NATIVE_PROFILE_MANIFEST_MAX_BYTES
            || read_u32(bytes, 68)? as usize != probe_len
            || bytes[72..80].iter().any(|byte| *byte != 0))
    {
        return Err(invalid("native-profile header"));
    }
    let declared = read_u32(bytes, 16)? as usize;
    let app_len = read_u32(bytes, 20)? as usize;
    let selectable_len = read_u32(bytes, 24)? as usize;
    let workspace_len = read_u32(bytes, 28)? as usize;
    if declared != bytes.len()
        || app_len > MAX_APP_RANDOM_BRANCH_PLAN_BYTES
        || selectable_len > SELECTABLE_CATALOG_PLAN_MAX_BYTES
        || !matches!(workspace_len, 0 | DEVICE_DIGEST_PURPOSE_BYTES)
        || read_u32(bytes, 32)? as usize != STARTUP_OPERATION_BYTES
        || read_u32(bytes, 36)? as usize != PURPOSE
    {
        return Err(invalid("lengths"));
    }
    let app_end = header.checked_add(app_len).ok_or(invalid("lengths"))?;
    let selectable_end = app_end
        .checked_add(selectable_len)
        .ok_or(invalid("lengths"))?;
    let workspace_end = selectable_end
        .checked_add(workspace_len)
        .ok_or(invalid("lengths"))?;
    let startup_end = workspace_end
        .checked_add(STARTUP_OPERATION_BYTES)
        .ok_or(invalid("lengths"))?;
    let purpose_end = startup_end.checked_add(PURPOSE).ok_or(invalid("lengths"))?;
    if purpose_end
        .checked_add(tail)
        .and_then(|end| end.checked_add(runtime_len))
        .and_then(|end| end.checked_add(native_len))
        .and_then(|end| end.checked_add(manifest_len))
        .and_then(|end| end.checked_add(probe_len))
        != Some(bytes.len())
    {
        return Err(invalid("lengths"));
    }
    let startup = StartupOperation::decode(&bytes[workspace_end..startup_end])
        .map_err(|source| PluginSetupPlanError::Startup { source })?;
    validate_binding(
        &startup,
        &bytes[startup_end..purpose_end],
        (workspace_len != 0).then_some(&bytes[selectable_end..workspace_end]),
    )?;

    if publisher {
        let subscription = match edition {
            Edition::DeferredCleanup
            | Edition::RuntimeArtifact
            | Edition::NativeTransfer
            | Edition::NativeProfile => {
                let purpose = crate::deferred_cleanup::DeferredCleanupPurpose::decode(
                    &bytes[purpose_end..purpose_end + tail],
                )
                .map_err(|_| invalid("deferred Cleanup purpose"))?;
                super::deferred_cleanup::validate_source_binding(
                    &purpose,
                    &bytes[startup_end..purpose_end],
                )?;
                purpose.publisher
            }
            Edition::Quantum => {
                crate::publisher_subscription::quantum::QuantumPublisherPurpose::decode(
                    &bytes[purpose_end..],
                )
                .map_err(|_| invalid("publisher purpose"))?
                .session
            }
            _ => crate::publisher_subscription::PublisherPurpose::decode(&bytes[purpose_end..])
                .map_err(|_| invalid("publisher purpose"))?,
        };
        super::publisher::validate_binding(&subscription, &bytes[startup_end..purpose_end])?;
        if runtime {
            let runtime_start = purpose_end + tail;
            let runtime_end = runtime_start + runtime_len;
            let pair = crate::runtime_artifact::RuntimeArtifactPair::decode(
                &bytes[runtime_start..runtime_end],
            )
            .map_err(|_| invalid("runtime-artifact pair"))?;
            super::runtime_artifact::validate_binding(&pair, &subscription)?;
            if native {
                let transfer = crate::native_transfer::NativeTransfer::decode(
                    &bytes[runtime_end..runtime_end + native_len],
                )
                .map_err(|_| invalid("native transfer"))?;
                transfer
                    .corroborate_runtime(&pair)
                    .map_err(|_| invalid("native-transfer binding"))?;
                if profile {
                    let manifest_start = runtime_end + native_len;
                    let probe_start = manifest_start + manifest_len;
                    let manifest = crate::native_transfer::manifest::NativeProfileManifest::decode(
                        &bytes[manifest_start..probe_start],
                    )
                    .map_err(|_| invalid("native-profile manifest"))?;
                    let probe = crate::native_transfer::probe::NativeProbeReport::decode(
                        &bytes[probe_start..],
                    )
                    .map_err(|_| invalid("native-profile probe"))?;
                    probe
                        .corroborate_transfer(&transfer, &manifest, &pair)
                        .map_err(|_| invalid("native-profile binding"))?;
                }
            }
        }
    }

    let app = AppRandomBranchPlan::decode(&bytes[header..app_end])
        .map_err(|source| PluginSetupPlanError::AppRandom { source })?;
    let selectable = SelectableCatalogPlan::decode(&bytes[app_end..selectable_end])
        .map_err(|source| PluginSetupPlanError::Selectable { source })?;
    Ok((app, selectable))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PluginSetupPlanError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(PluginSetupPlanError::Truncated)?;
    Ok(u64::from_be_bytes(
        value
            .try_into()
            .map_err(|_| PluginSetupPlanError::Truncated)?,
    ))
}

pub(super) fn validate_binding(
    startup: &StartupOperation,
    purpose: &[u8],
    workspace: Option<&[u8]>,
) -> Result<(), PluginSetupPlanError> {
    let invalid = |section| PluginSetupPlanError::InvalidPreexecSection { section };
    if purpose.len() != PURPOSE
        || workspace.is_some_and(|bytes| bytes.len() != DEVICE_DIGEST_PURPOSE_BYTES)
    {
        return Err(invalid("lengths"));
    }
    if purpose[..8] != *b"CRUCPUR8"
        || read_u32(purpose, 8)? != 8
        || read_u32(purpose, 12)? as usize != PURPOSE
        || purpose[16..24] != startup.fields().original_total_metadata_bytes.to_be_bytes()
        || purpose[96..104] != startup.fields().process_generation.to_be_bytes()
        || purpose[184..216] != startup.fields().cap_id
        || read_u64(purpose, 520)? == 0
        || read_u64(purpose, 528)? == 0
        || read_u64(purpose, 536)? != 100_000
        || read_u64(purpose, 544)? == 0
        || !matches!(read_u64(purpose, 552)?, 1..=0xffff_ffff)
        || !matches!(read_u64(purpose, 560)?, 1..=0xffff_ffff)
    {
        return Err(invalid("process purpose"));
    }
    validate_ram_endpoint(purpose)?;
    family::validate(purpose)?;
    validate_standing_source(purpose)?;

    if let Some(workspace) = workspace
        && (workspace[..8] != *b"CRUCWSP2"
            || read_u32(workspace, 8)? != 2
            || read_u32(workspace, 12)? != 1
            || workspace[16..48] != purpose[184..216]
            || workspace[48..56] != purpose[16..24]
            || workspace[72..80] != purpose[96..104]
            || workspace[80..88] != purpose[88..96]
            || workspace[64..72] != crate::DEVICE_DIGEST_WORKSPACE_BYTES.to_be_bytes()
            || workspace[112..120] != [0; 8]
            || workspace[120..128] != workspace[64..72])
    {
        return Err(invalid("workspace"));
    }

    Ok(())
}

/// Checks endpoint syntax; the genuine issuer and native owner check identity.
fn validate_ram_endpoint(purpose: &[u8]) -> Result<(), PluginSetupPlanError> {
    let endpoint = &purpose[568..744];
    if endpoint.iter().all(|byte| *byte == 0) {
        // Resident launches may omit RAM control. An absent binding cannot lend
        // the inherited socket to a native RAM actor.
        return Ok(());
    }

    // Match the existing RAM control codec's canonical session and Target
    // syntax. The issuer separately compares the exact registered Target;
    // these checks do not authenticate copied endpoint facts or identities.
    if read_u64(purpose, 576)? == 0
        || read_u64(purpose, 584)? == 0
        || purpose[592..624] == [0; 32]
        || purpose[624..656] == [0; 32]
        || purpose[656..688] == [0; 32]
        || purpose[688..720] == [0; 32]
        || read_u64(purpose, 720)? != read_u64(purpose, 96)?
        || read_u64(purpose, 728)? == 0
        || purpose[736] > 1
        || purpose[737..744] != [0; 7]
    {
        return Err(PluginSetupPlanError::InvalidPreexecSection {
            section: "RAM endpoint",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;

fn validate_standing_source(purpose: &[u8]) -> Result<(), PluginSetupPlanError> {
    let invalid = || PluginSetupPlanError::InvalidPreexecSection {
        section: "standing Source",
    };
    let tail = purpose.get(1000..2520).ok_or_else(invalid)?;
    if read_u64(tail, 8)? == 0 || read_u64(tail, 16)? != 1504 {
        return Err(invalid());
    }
    let source = crate::source_supervision::decode_source_supervision_payload(&tail[24..])
        .map_err(|_| invalid())?;
    if source.cap != purpose[184..216]
        || source.cap != purpose[760..792]
        || source.account_generation != read_u64(purpose, 88)?
        || source.process_generation != read_u64(purpose, 96)?
        || source.reservation != purpose[816..848]
        || source.artifact != purpose[144..176]
    {
        return Err(invalid());
    }
    Ok(())
}
