//! Nonauthorizing public-area and complete-map DATA for closed TPM purposes.
//!
//! Only the deployment namespace-27 head is supported here. These projections
//! neither open a TPM nor admit a provisioned floor, authenticate currentness,
//! construct startup custody or enable an effect. The bounded credential
//! reader is shared downward by existing role-specific admission adapters.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

use crate::journal::RecordNamespace;

#[doc(hidden)]
pub mod credential;

mod role_binding;
mod root;

pub use root::{
    FAILED_CREATE_ORIGINAL_HISTORIES_MAXIMUM_BYTES_V4, FailedCreateOriginalHistoriesDataV4,
    FailedCreateOriginalHistoryErrorV4, encode_failed_create_original_histories_v4,
    failed_create_original_histories_encoded_len_v4,
};

/// Names an independently provisioned fixed-purpose NV index as inert DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NvCustodyEndpointV1 {
    ControllerStorageClient,
    StorageBroker,
    RuntimeDeployment,
    RootCreateFailure,
    ControllerNix,
    NixOwner,
}

impl NvCustodyEndpointV1 {
    pub(crate) const fn nv_index(self) -> u32 {
        match self {
            Self::ControllerStorageClient => 0x0180_a046,
            Self::StorageBroker => 0x0180_a047,
            Self::RuntimeDeployment => 0x0180_a055,
            Self::RootCreateFailure => 0x0180_a053,
            Self::ControllerNix => 0x0180_a058,
            Self::NixOwner => 0x0180_a059,
        }
    }
}

/// Classifies projection failures without granting retry or floor authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NvCustodyErrorV1 {
    #[error("invalid private TPM carrier framing")]
    Encoding,
    #[error("private TPM carrier provisioning mismatch")]
    Provisioning,
    #[error("private TPM carrier unavailable")]
    Unavailable,
}

/// Computes canonical public-area Name DATA, not an authenticated observation.
pub(crate) fn canonical_nv_name_v1(endpoint: NvCustodyEndpointV1) -> [u8; 34] {
    let mut public = [0; 14];
    public[..4].copy_from_slice(&endpoint.nv_index().to_be_bytes());
    public[4..6].copy_from_slice(&0x000b_u16.to_be_bytes());
    public[6..10].copy_from_slice(&0x2004_0044_u32.to_be_bytes());
    public[12..14].copy_from_slice(&32_u16.to_be_bytes());

    let mut name = [0; 34];
    name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
    name[2..].copy_from_slice(&Sha256::digest(public));
    name
}

/// Computes the exact borrowed complete-map deployment head as inert DATA.
///
/// The caller's complete purpose codec owns row/byte bounds. Unsupported
/// purposes remain unavailable rather than acquiring a guessed namespace.
///
/// # Errors
///
/// Rejects zero or exhausted sequences, empty keys and nondeployment purposes.
pub(crate) fn canonical_purpose_main_head_v1(
    endpoint: NvCustodyEndpointV1,
    scope: [u8; 32],
    sequence: u64,
    records: &BTreeMap<&[u8], &[u8]>,
) -> Result<[u8; 32], NvCustodyErrorV1> {
    if sequence == 0 || sequence == u64::MAX {
        return Err(NvCustodyErrorV1::Encoding);
    }
    if endpoint != NvCustodyEndpointV1::RuntimeDeployment {
        return Err(NvCustodyErrorV1::Provisioning);
    }

    let mut hash = Sha256::new()
        .chain_update(b"aos.sandbox.tpm-floor.closed-purpose.head.v1\0")
        .chain_update(scope)
        .chain_update([RecordNamespace::HostCatalogReconciliation as u8])
        .chain_update(sequence.to_be_bytes());
    for (key, value) in records {
        if key.is_empty() {
            return Err(NvCustodyErrorV1::Encoding);
        }
        hash.update((key.len() as u64).to_be_bytes());
        hash.update(key);
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update((records.len() as u64).to_be_bytes());
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrun_canonical_name_preserves_the_exact_public_area_for_every_endpoint() {
        let endpoints = [
            (NvCustodyEndpointV1::ControllerStorageClient, 0x0180_a046_u32),
            (NvCustodyEndpointV1::StorageBroker, 0x0180_a047),
            (NvCustodyEndpointV1::RuntimeDeployment, 0x0180_a055),
            (NvCustodyEndpointV1::RootCreateFailure, 0x0180_a053),
            (NvCustodyEndpointV1::ControllerNix, 0x0180_a058),
            (NvCustodyEndpointV1::NixOwner, 0x0180_a059),
        ];
        let mut names = std::collections::BTreeSet::new();

        for (endpoint, index) in endpoints {
            let mut public = index.to_be_bytes().to_vec();
            public.extend_from_slice(&[
                0x00, 0x0b, 0x20, 0x04, 0x00, 0x44, 0x00, 0x00, 0x00, 0x20,
            ]);
            assert_eq!(public.len(), 14);

            let name = canonical_nv_name_v1(endpoint);
            assert_eq!(endpoint.nv_index(), index);
            assert_eq!(&name[..2], &[0x00, 0x0b]);
            assert_eq!(&name[2..], Sha256::digest(public).as_slice());
            assert!(names.insert(name));
        }
    }

    #[test]
    fn unrun_host_head_preserves_complete_sorted_byte_framing() {
        let rows = BTreeMap::from([
            (b"beta".as_slice(), b"two".as_slice()),
            (b"alpha".as_slice(), b"one".as_slice()),
        ]);
        let mut framed = b"aos.sandbox.tpm-floor.closed-purpose.head.v1\0".to_vec();
        framed.extend_from_slice(&[7; 32]);
        framed.push(27);
        framed.extend_from_slice(&9_u64.to_be_bytes());
        for (key, value) in [
            (b"alpha".as_slice(), b"one".as_slice()),
            (b"beta".as_slice(), b"two".as_slice()),
        ] {
            framed.extend_from_slice(&(key.len() as u64).to_be_bytes());
            framed.extend_from_slice(key);
            framed.extend_from_slice(&(value.len() as u64).to_be_bytes());
            framed.extend_from_slice(value);
        }
        framed.extend_from_slice(&2_u64.to_be_bytes());

        let head = canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment,
            [7; 32],
            9,
            &rows,
        )
        .unwrap();

        assert_eq!(RecordNamespace::HostCatalogReconciliation as u8, 27);
        assert_eq!(head, <[u8; 32]>::from(Sha256::digest(framed)));
        let insertion_reversed = BTreeMap::from([
            (b"alpha".as_slice(), b"one".as_slice()),
            (b"beta".as_slice(), b"two".as_slice()),
        ]);
        let reordered_head = canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment,
            [7; 32],
            9,
            &insertion_reversed,
        )
        .unwrap();
        assert_eq!(head, reordered_head);

        let changed_rows = [
            BTreeMap::from([(b"alpha".as_slice(), b"one".as_slice())]),
            BTreeMap::from([
                (b"alpha".as_slice(), b"one".as_slice()),
                (b"beta".as_slice(), b"changed".as_slice()),
            ]),
            BTreeMap::from([
                (b"alpha".as_slice(), b"one".as_slice()),
                (b"gamma".as_slice(), b"two".as_slice()),
            ]),
        ];
        for changed in changed_rows {
            let changed_head = canonical_purpose_main_head_v1(
                NvCustodyEndpointV1::RuntimeDeployment,
                [7; 32],
                9,
                &changed,
            )
            .unwrap();
            assert_ne!(head, changed_head);
        }
        for (scope, sequence) in [([8; 32], 9), ([7; 32], 10)] {
            let changed_head = canonical_purpose_main_head_v1(
                NvCustodyEndpointV1::RuntimeDeployment,
                scope,
                sequence,
                &rows,
            )
            .unwrap();
            assert_ne!(head, changed_head);
        }
    }

    #[test]
    fn unrun_host_head_retains_closed_purpose_and_encoding_refusals() {
        let empty = BTreeMap::new();
        for sequence in [0, u64::MAX] {
            let result = canonical_purpose_main_head_v1(
                NvCustodyEndpointV1::RuntimeDeployment,
                [1; 32],
                sequence,
                &empty,
            );
            assert_eq!(result, Err(NvCustodyErrorV1::Encoding));
        }
        let empty_key = BTreeMap::from([(b"".as_slice(), b"value".as_slice())]);
        let result = canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment,
            [1; 32],
            1,
            &empty_key,
        );
        assert_eq!(result, Err(NvCustodyErrorV1::Encoding));

        for endpoint in [
            NvCustodyEndpointV1::ControllerStorageClient,
            NvCustodyEndpointV1::StorageBroker,
            NvCustodyEndpointV1::RootCreateFailure,
            NvCustodyEndpointV1::ControllerNix,
            NvCustodyEndpointV1::NixOwner,
        ] {
            let result = canonical_purpose_main_head_v1(endpoint, [1; 32], 1, &empty);
            assert_eq!(result, Err(NvCustodyErrorV1::Provisioning));
        }
        assert!(canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment,
            [1; 32],
            u64::MAX - 1,
            &empty,
        )
        .is_ok());
    }
}
