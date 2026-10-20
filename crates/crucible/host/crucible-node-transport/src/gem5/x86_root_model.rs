//! Authenticates x86 root native Ready against the actual installed PC selection.
//!
//! Native readiness is a private stopped-channel fact. It is not a common Ready
//! attestation, Linux PID1 success, device-parity report or current capture seal.

use crucible_node_format::{Id, U64, Validate};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::refusal::Gem5DiagnosticCreditPolicy;
use super::{Gem5Boundary, Gem5ConfigurationTree, Gem5ModelAsset, Gem5ModelDialect};
use crate::ProviderError;

pub(crate) struct X86RootSelection {
    pub(crate) kernel: Box<Gem5ModelAsset>,
    pub(crate) initramfs: Box<Gem5ModelAsset>,
    pub(crate) configuration: Gem5ConfigurationTree,
    pub(crate) loader: Value,
}

/// Retains exactly the two genuine x86 Linux guest assets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5X86RootNativeAssets {
    /// Binds the original installed Linux ELF bytes.
    pub kernel: super::model::Gem5NativeAssetBinding,
    /// Binds the original installed PID1 initramfs bytes.
    pub initramfs: super::model::Gem5NativeAssetBinding,
}

/// Retains the distinct root realization without promoting mechanism flags.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5X86RootNativeScope {
    /// Names the unchanged native model-scope grammar.
    pub schema: String,
    /// Identifies the source-owned parent-zero PC model.
    pub model_id: String,
    /// Reports actual full-system construction rather than SE stdout emulation.
    pub full_system: bool,
    /// Remains false; complete live byte closure has its own current certificate.
    pub complete_process_closure_qualified: bool,
    /// Remains false for this functional Atomic CPU.
    pub cpu_timing_qualified: bool,
    /// Remains false; native construction does not prove guest readiness.
    pub guest_readiness_qualified: bool,
    /// Remains false until genuine complete guest-visible ABI qualification.
    pub device_parity_qualified: bool,
    /// Retains the original kernel and initramfs measured by the native model.
    pub guest_assets: Gem5X86RootNativeAssets,
    /// Binds the complete source-owned board configuration tree.
    pub configuration_tree: Gem5ConfigurationTree,
    /// Retains the actual closed x86 loader description, compared to installed data.
    pub loader: Value,
}

/// Retains native Ready under the explicitly installed x86 root model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5X86RootNativeReady {
    /// Identifies the private native readiness response.
    pub kind: String,
    /// Selects the x86 native protocol without ARM or SE fallback.
    pub schema: Gem5ModelDialect,
    /// Identifies the original indivisible execution owner.
    pub owner: Id,
    /// Identifies this newly constructed or reconstructed native incarnation.
    pub incarnation: Id,
    /// Fences prior native incarnations monotonically.
    pub generation: U64,
    /// Retains actual Original, Captured, Reconnected or Restored routing provenance.
    pub continuation: String,
    /// Binds finite original diagnostic reservation and refusal custody.
    pub diagnostic_credit_policy: Gem5DiagnosticCreditPolicy,
    /// Retains the actual parked callback and logical boundary.
    pub boundary: Gem5Boundary,
    /// Retains original source/model/loader data without granting node authority.
    pub model_scope: Gem5X86RootNativeScope,
}

impl Gem5X86RootNativeReady {
    pub(crate) fn validate_selection(
        &self,
        selection: &X86RootSelection,
        owner: &Id,
        incarnation: &Id,
        generation: U64,
    ) -> Result<(), ProviderError> {
        validate_loader_data(&selection.loader)?;
        if loader_integer(&selection.loader["kernel_bytes"])?
            != selection.kernel.content.length.get()
            || loader_integer(&selection.loader["initramfs_bytes"])?
                != selection.initramfs.content.length.get()
        {
            return Err(ProviderError::Correlation(
                "x86 loader and original guest extents differ",
            ));
        }
        owner.validate()?;
        incarnation.validate()?;
        let policy = &self.diagnostic_credit_policy;
        let scope = &self.model_scope;
        if generation.get() == 0
            || self.kind != "ready"
            || self.schema != Gem5ModelDialect::X86Linux
            || &self.owner != owner
            || &self.incarnation != incarnation
            || self.generation != generation
            || !matches!(
                self.continuation.as_str(),
                "original" | "reconnected" | "captured" | "restored"
            )
            || policy.schema != "crucible.gem5.diagnostic-credit-policy.v1"
            || policy.refusal_schema != "crucible.gem5.run-refused.v1"
            || policy.maximum_object_bytes.get() != 64 * 1024 * 1024
            || policy.maximum_total_bytes.get() != 256 * 1024 * 1024
            || policy.maximum_files.get() != 1024
            || scope.schema != "crucible.gem5.model-scope.v1"
            || scope.model_id != "x86-linux-pc-atomic-root-functional-v1"
            || !scope.full_system
            || scope.complete_process_closure_qualified
            || scope.cpu_timing_qualified
            || scope.guest_readiness_qualified
            || scope.device_parity_qualified
            || scope.configuration_tree != selection.configuration
            || scope.loader != selection.loader
        {
            return Err(ProviderError::Correlation(
                "x86 root Ready differs from original installed custody",
            ));
        }
        for (observed, original, basename) in [
            (&scope.guest_assets.kernel, &selection.kernel, "kernel.elf"),
            (
                &scope.guest_assets.initramfs,
                &selection.initramfs,
                "initrd.img",
            ),
        ] {
            original.content.validate()?;
            if original.file != basename
                || original.content.length.get() == 0
                || observed.bytes != original.content.length
                || observed.sha256 != original.sha256
            {
                return Err(ProviderError::Correlation(
                    "x86 root native guest asset differs",
                ));
            }
        }
        Ok(())
    }
}

fn loader_integer(value: &Value) -> Result<u64, ProviderError> {
    let text = value
        .as_str()
        .ok_or(ProviderError::Frame("x86 loader integer is not a string"))?;
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProviderError::Frame("x86 loader integer is not canonical"));
    }
    text.parse()
        .map_err(|_| ProviderError::Frame("x86 loader integer overflows"))
}

pub(crate) fn validate_loader_data(loader: &Value) -> Result<(), ProviderError> {
    const KEYS: [&str; 12] = [
        "schema",
        "ram_bytes",
        "kernel_bytes",
        "entry_point",
        "load_addr_mask",
        "load_addr_offset",
        "native_reserved_range",
        "kernel_load_segments",
        "initramfs_address",
        "initramfs_bytes",
        "boot_parameters",
        "linux_boot_protocol",
    ];
    let fields = loader
        .as_object()
        .ok_or(ProviderError::Frame("x86 loader data is not an object"))?;
    let keys = &KEYS;
    if fields.len() != keys.len()
        || keys.iter().any(|key| !fields.contains_key(*key))
        || loader["schema"] != "crucible.gem5.x86-linux-loader.v1"
        || loader["linux_boot_protocol"] != "x86-boot-params-initrd-low32-v1"
        || loader_integer(&loader["ram_bytes"])? != 256 * 1024 * 1024
        || loader_integer(&loader["load_addr_mask"])? != u64::MAX
        || loader_integer(&loader["load_addr_offset"])? != 0
        || loader_integer(&loader["initramfs_address"])? != 192 * 1024 * 1024
        || loader_integer(&loader["boot_parameters"])? != 0x90200
    {
        return Err(ProviderError::Frame(
            "x86 loader differs from the fixed native boot ABI",
        ));
    }
    let kernel_bytes = loader_integer(&loader["kernel_bytes"])?;
    let initramfs_bytes = loader_integer(&loader["initramfs_bytes"])?;
    let entry = loader_integer(&loader["entry_point"])?;
    let reserved = loader["native_reserved_range"]
        .as_array()
        .filter(|range| range.len() == 2)
        .ok_or(ProviderError::Frame("x86 reserved range geometry"))?;
    if kernel_bytes == 0
        || kernel_bytes > 1024 * 1024 * 1024
        || initramfs_bytes == 0
        || initramfs_bytes > 32 * 1024 * 1024
        || loader_integer(&reserved[0])? != 0
        || loader_integer(&reserved[1])? != 1024 * 1024
    {
        return Err(ProviderError::Frame(
            "x86 loader guest extent or reserved region differs",
        ));
    }
    let segments = loader["kernel_load_segments"]
        .as_array()
        .filter(|segments| !segments.is_empty() && segments.len() <= 128)
        .ok_or(ProviderError::Frame("x86 kernel load segment census"))?;
    let mut entry_backed = false;
    for (index, segment) in segments.iter().enumerate() {
        let row = segment
            .as_array()
            .filter(|row| row.len() == 2)
            .ok_or(ProviderError::Frame("x86 kernel load segment geometry"))?;
        let start = loader_integer(&row[0])?;
        let bytes = loader_integer(&row[1])?;
        let end = start
            .checked_add(bytes)
            .ok_or(ProviderError::Frame("x86 kernel load segment overflow"))?;
        if start < 1024 * 1024
            || bytes == 0
            || end > 256 * 1024 * 1024
            || (start < 192 * 1024 * 1024 + initramfs_bytes && 192 * 1024 * 1024 < end)
        {
            return Err(ProviderError::Frame(
                "x86 kernel load backing overlaps reserved bytes",
            ));
        }
        for previous in &segments[..index] {
            let previous = previous
                .as_array()
                .ok_or(ProviderError::Frame("x86 kernel prior segment geometry"))?;
            let old_start = loader_integer(&previous[0])?;
            let old_end = old_start
                .checked_add(loader_integer(&previous[1])?)
                .ok_or(ProviderError::Frame("x86 kernel prior segment overflow"))?;
            if start < old_end && old_start < end {
                return Err(ProviderError::Frame("x86 kernel load segment aliases"));
            }
        }
        entry_backed |= start <= entry && entry < end;
    }
    if !entry_backed {
        return Err(ProviderError::Frame(
            "x86 native entry lacks selected segment backing",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Phase, Position, canonical};
    use serde_json::json;

    fn selection() -> Result<X86RootSelection, ProviderError> {
        let document: Value = serde_json::from_str(include_str!("x86-root-scope-fixture.json"))
            .map_err(|_| ProviderError::Frame("inert x86 scope fixture"))?;
        let asset = |file: &str| -> Result<Box<Gem5ModelAsset>, ProviderError> {
            Ok(Box::new(Gem5ModelAsset {
                file: file.to_owned(),
                content: canonical::content_ref(&[0; 4096], "application/octet-stream")?,
                sha256: "0".repeat(64),
            }))
        };
        Ok(X86RootSelection {
            kernel: asset("kernel.elf")?,
            initramfs: asset("initrd.img")?,
            configuration: serde_json::from_value(document["model"]["configuration_tree"].clone())
                .map_err(|_| ProviderError::Frame("inert x86 configuration fixture"))?,
            loader: document["model"]["loader_geometry"].clone(),
        })
    }

    fn ready(selection: &X86RootSelection) -> Result<Gem5X86RootNativeReady, ProviderError> {
        let binding = |asset: &Gem5ModelAsset| super::super::model::Gem5NativeAssetBinding {
            bytes: asset.content.length,
            sha256: asset.sha256.clone(),
        };
        Ok(Gem5X86RootNativeReady {
            kind: "ready".to_owned(),
            schema: Gem5ModelDialect::X86Linux,
            owner: Id::new("inert-owner")?,
            incarnation: Id::new("inert-incarnation")?,
            generation: 1.into(),
            continuation: "original".to_owned(),
            diagnostic_credit_policy: Gem5DiagnosticCreditPolicy {
                schema: "crucible.gem5.diagnostic-credit-policy.v1".to_owned(),
                refusal_schema: "crucible.gem5.run-refused.v1".to_owned(),
                maximum_object_bytes: (64 * 1024 * 1024).into(),
                maximum_total_bytes: (256 * 1024 * 1024).into(),
                maximum_files: 1024.into(),
            },
            boundary: Gem5Boundary {
                tick: 0.into(),
                ordinal: 0.into(),
                tick_ordinal: 0.into(),
                logical_position: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
                has_next_event: true,
                next_tick: 1.into(),
                next_priority: 0,
                inventory: json!({"complete": false}),
            },
            model_scope: Gem5X86RootNativeScope {
                schema: "crucible.gem5.model-scope.v1".to_owned(),
                model_id: "x86-linux-pc-atomic-root-functional-v1".to_owned(),
                full_system: true,
                complete_process_closure_qualified: false,
                cpu_timing_qualified: false,
                guest_readiness_qualified: false,
                device_parity_qualified: false,
                guest_assets: Gem5X86RootNativeAssets {
                    kernel: binding(&selection.kernel),
                    initramfs: binding(&selection.initramfs),
                },
                configuration_tree: selection.configuration.clone(),
                loader: selection.loader.clone(),
            },
        })
    }

    #[test]
    fn original_x86_root_data_binds_two_assets_without_minting_live_authority()
    -> Result<(), ProviderError> {
        let selection = selection()?;
        let ready = ready(&selection)?;
        ready.validate_selection(&selection, &ready.owner, &ready.incarnation, 1.into())?;
        assert!(!ready.model_scope.complete_process_closure_qualified);
        assert!(!ready.model_scope.guest_readiness_qualified);
        assert!(!ready.model_scope.device_parity_qualified);
        Ok(())
    }

    #[test]
    fn old_model_wrong_peer_asset_or_capability_claim_is_refused() -> Result<(), ProviderError> {
        let selection = selection()?;
        let original = ready(&selection)?;
        for change in 0..10 {
            let mut changed = original.clone();
            match change {
                0 => changed.model_scope.model_id = "x86-linux-pc-atomic-functional-v1".to_owned(),
                1 => changed.schema = Gem5ModelDialect::ArmLinux,
                2 => changed.owner = Id::new("another-owner")?,
                3 => changed.incarnation = Id::new("another-incarnation")?,
                4 => changed.generation = 2.into(),
                5 => changed.model_scope.guest_assets.kernel.bytes = 4095.into(),
                6 => changed.model_scope.guest_assets.initramfs.sha256 = "1".repeat(64),
                7 => changed.model_scope.device_parity_qualified = true,
                8 => changed.model_scope.loader["entry_point"] = json!("2097153"),
                _ => changed.model_scope.configuration_tree.files = 167.into(),
            }
            assert!(
                changed
                    .validate_selection(
                        &selection,
                        &original.owner,
                        &original.incarnation,
                        1.into()
                    )
                    .is_err(),
                "change {change}"
            );
        }
        Ok(())
    }

    #[test]
    fn loader_reserved_overlap_alias_and_unfunded_extent_refuse() -> Result<(), ProviderError> {
        let selected = selection()?;
        validate_loader_data(&selected.loader)?;
        for change in 0..8 {
            let mut loader = selected.loader.clone();
            match change {
                0 => loader["kernel_load_segments"] = json!([["0", "4096"]]),
                1 => loader["kernel_load_segments"] = json!([["201326591", "2"]]),
                2 => {
                    loader["kernel_load_segments"] = json!([["2097152", "4096"], ["2097153", "1"]])
                }
                3 => loader["entry_point"] = json!("2101248"),
                4 => loader["kernel_load_segments"] = json!([["18446744073709551615", "1"]]),
                5 => loader["initramfs_bytes"] = json!("33554433"),
                6 => loader["kernel_bytes"] = json!("04096"),
                _ => loader["unknown"] = json!("unrecognized"),
            }
            assert!(validate_loader_data(&loader).is_err(), "change {change}");
        }
        let mut unfunded = selection()?;
        unfunded.kernel.content.length = 4095.into();
        let observed = ready(&selected)?;
        assert!(
            observed
                .validate_selection(&unfunded, &observed.owner, &observed.incarnation, 1.into())
                .is_err()
        );
        Ok(())
    }
}
