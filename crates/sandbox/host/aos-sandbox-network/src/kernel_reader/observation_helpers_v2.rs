//! Selects closed observation recipes on ordinary or genuine Source borrowers.
//!
//! Command construction is shared. The Source branch owns no signer, bank,
//! mutation role or caller-supplied argv. Its sealed read borrower and actual
//! native Source are prerequisites; these recipes cannot construct either.

use super::*;
use crate::kernel_mutator::NetworkStatusHelperRoleV4;

mod opening;
mod receiving;
mod source;

pub(crate) use opening::NetworkObservationReadersOriginalV2;
pub(crate) use receiving::{
    ObservationJsonLayoutDataV2, ObservationProgrammeDataV2, observation_programme_data_v2,
    json_receiving_bytes_data_v2,
};
pub(crate) use source::{
    NetworkObservationReadProgrammeOriginalV2, NetworkObservationSourcePortV2,
    ReadFrontierOriginalV2,
};

/// Names only the literal inventory commands used by the existing readers.
pub(crate) enum ObservationRecipeV2<'plan> {
    Links(Option<&'plan str>),
    Addresses(Option<&'plan str>),
    Neighbors(Option<&'plan str>),
    Routes { ipv6: bool },
    Rules { ipv6: bool },
    NftPolicy,
    NftTables,
    BpfGraph { handle: [u8; 32], absent: bool },
}

impl ObservationRecipeV2<'_> {
    fn argument_storage_bytes_data_v2() -> Option<usize> {
        let nft = [
            "--json",
            "--handle",
            "--numeric",
            "--numeric-priority",
            "list",
            "table",
            "inet",
            "aos_sandbox",
        ]
        .into_iter()
        .try_fold(0usize, |bytes, word| bytes.checked_add(word.len()))?;
        let bpf = BPF_PIN_PREFIX
            .len()
            .checked_add(1 + 64)?
            .checked_add("--expect-absent".len())?;
        let ip = ["-j", "-details", "link", "show", "dev"]
            .into_iter()
            .try_fold(15usize, |bytes, word| bytes.checked_add(word.len()))?;
        // The literal selector Vec and the final OsString Vec can coexist.
        std::mem::size_of::<OsString>()
            .checked_mul(16)?
            .checked_add(nft.max(bpf).max(ip).checked_mul(2)?)
    }

    fn arguments(&self) -> Result<Vec<OsString>, NetworkKernelReaderError> {
        let (mut arguments, device) = match self {
            Self::Links(device) => (vec!["-j", "-details", "link", "show"], *device),
            Self::Addresses(device) => (vec!["-j", "address", "show"], *device),
            Self::Neighbors(device) => (vec!["-j", "-6", "neighbor", "show"], *device),
            Self::Routes { ipv6 } => (
                vec![
                    "-j",
                    if *ipv6 { "-6" } else { "-4" },
                    "route",
                    "show",
                    "table",
                    "all",
                ],
                None,
            ),
            Self::Rules { ipv6 } => (
                vec!["-j", if *ipv6 { "-6" } else { "-4" }, "rule", "show"],
                None,
            ),
            Self::NftPolicy => (
                vec![
                    "--json",
                    "--handle",
                    "--numeric",
                    "--numeric-priority",
                    "list",
                    "table",
                    "inet",
                    "aos_sandbox",
                ],
                None,
            ),
            Self::NftTables => (vec!["--json", "--handle", "list", "tables"], None),
            Self::BpfGraph { handle, absent } => {
                if *handle == [0; 32] {
                    return Err(NetworkKernelReaderError::InvalidBpf(
                        "network handle is zero",
                    ));
                }
                let pin_root = format!("{BPF_PIN_PREFIX}/{}", encode_hex(*handle));
                return Ok(if *absent {
                    vec![OsString::from("--expect-absent"), OsString::from(pin_root)]
                } else {
                    vec![OsString::from(pin_root)]
                });
            }
        };
        if let Some(name) = device {
            if name.is_empty()
                || name.len() > 15
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                return Err(NetworkKernelReaderError::InvalidRtnetlink(
                    "invalid plan-derived interface name",
                ));
            }
            arguments.extend(["dev", name]);
        }
        Ok(arguments.into_iter().map(OsString::from).collect())
    }

    fn role(&self) -> NetworkStatusHelperRoleV4 {
        use NetworkStatusHelperRoleV4 as Role;
        match self {
            Self::Links(_) => Role::IpLinks,
            Self::Addresses(_) => Role::IpAddresses,
            Self::Neighbors(_) => Role::IpNeighbors,
            Self::Routes { .. } => Role::IpRoutes,
            Self::Rules { .. } => Role::IpRules,
            Self::NftPolicy | Self::NftTables => Role::NftPolicy,
            Self::BpfGraph { .. } => Role::BpfGraph,
        }
    }

    fn artifact_role(&self) -> NetworkArtifactRoleV4 {
        match self {
            Self::NftPolicy | Self::NftTables => NetworkArtifactRoleV4::Nft,
            Self::BpfGraph { .. } => NetworkArtifactRoleV4::BpfObserver,
            _ => NetworkArtifactRoleV4::Ip,
        }
    }

    fn maximum_stdout(&self) -> usize {
        match self {
            Self::Links(_) => crate::rtnetlink_reader::MAXIMUM_LINK_BYTES,
            Self::Addresses(_) => crate::rtnetlink_reader::MAXIMUM_ADDRESS_BYTES,
            Self::Neighbors(_) => crate::rtnetlink_reader::MAXIMUM_NEIGHBOR_BYTES,
            Self::Routes { .. } => crate::rtnetlink_reader::MAXIMUM_ROUTE_BYTES,
            Self::Rules { .. } => crate::rtnetlink_reader::MAXIMUM_RULE_BYTES,
            Self::NftPolicy | Self::NftTables => {
                crate::nftables_reader::MAXIMUM_NFTABLES_OBSERVATION_BYTES
            }
            Self::BpfGraph { .. } => MAXIMUM_BPF_OBSERVATION_BYTES,
        }
    }
}

/// Names the two actual immutable provenance operands, never an executable role.
#[derive(Clone, Copy)]
pub(crate) enum ObservationAttestationV2 {
    Enforcement,
    LeaseObject,
}

impl ObservationAttestationV2 {
    fn role(self) -> NetworkArtifactRoleV4 {
        match self {
            Self::Enforcement => NetworkArtifactRoleV4::Enforcement,
            Self::LeaseObject => NetworkArtifactRoleV4::LeaseObject,
        }
    }
}

/// Shares the reader engine while keeping the genuine Source path private.
pub(crate) enum ObservationHelperPortV2<'scope, 'held, 'native> {
    Local,
    Source(NetworkObservationSourcePortV2<'scope, 'held, 'native>),
}

impl ObservationHelperPortV2<'_, '_, '_> {
    pub(crate) fn nft_layout_data_v2(
        &self,
        absent: bool,
    ) -> Result<Option<ObservationJsonLayoutDataV2>, NetworkKernelReaderError> {
        match self {
            Self::Local => Ok(None),
            Self::Source(source) => source.nft_layout_data_v2(absent).map(Some),
        }
    }

    pub(crate) fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }

    pub(crate) fn run(
        &mut self,
        artifact: &PinnedArtifact,
        recipe: ObservationRecipeV2<'_>,
    ) -> Result<Vec<u8>, NetworkKernelReaderError> {
        match self {
            Self::Local => successful_helper_stdout(
                artifact.run(&recipe.arguments()?, recipe.maximum_stdout())?,
            ),
            Self::Source(source) => source.run(artifact, None, recipe),
        }
    }

    pub(crate) fn run_attested(
        &mut self,
        artifact: &PinnedArtifact,
        attestation: (&PinnedArtifact, ObservationAttestationV2),
        recipe: ObservationRecipeV2<'_>,
    ) -> Result<Vec<u8>, NetworkKernelReaderError> {
        match self {
            Self::Local => {
                attestation.0.validate_current()?;
                let stdout = successful_helper_stdout(
                    artifact.run(&recipe.arguments()?, recipe.maximum_stdout())?,
                )?;
                attestation.0.validate_current()?;
                Ok(stdout)
            }
            Self::Source(source) => source.run(artifact, Some(attestation), recipe),
        }
    }

    /// Disposes only completed native helpers after the actual semantic Result
    /// has been parked by the same reader. This supplies no positive grant.
    pub(crate) fn finish_group(&mut self) -> Result<(), NetworkKernelReaderError> {
        match self {
            Self::Local => Ok(()),
            Self::Source(source) => source.finish_group(),
        }
    }

    pub(crate) fn require_boundary_once(&mut self) -> Result<(), NetworkKernelReaderError> {
        match self {
            Self::Local => Ok(()),
            Self::Source(source) => source.require_boundary_once(),
        }
    }
}

/// Keeps a semantic refusal primary while executing the owed native disposal.
pub(crate) fn finish_read_group_v2<T>(
    result: Result<T, NetworkKernelReaderError>,
    port: &mut ObservationHelperPortV2<'_, '_, '_>,
) -> Result<T, NetworkKernelReaderError> {
    let disposal = port.finish_group();
    match result {
        Err(cause) => Err(cause),
        Ok(value) => disposal.map(|()| value),
    }
}
