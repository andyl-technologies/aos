//! Shares canonical ONLINE058/059 provisioning profile DATA.
//!
//! Independent provisioning and runtime consumption use the same fixed route,
//! written NV Name and journal geometry. These bytes confer no startup, signer,
//! journal custody, TPM observation or currentness authority.
//!
//! ```text
//! AOSNXF02/version2/reserved | role/padding | node/deployment/endpoint/domain |
//! commitments/public-set/startup/stable-endpoint/genesis/issuer/auth |
//! salt-Name/written-NV-Name | eight-main-limits | route/snapshot
//! ```

use aos_sandbox_model::journal_namespace::RecordNamespace;
use sha2::{Digest as _, Sha256};

/// Fixes the canonical version-two profile width.
pub const PROFILE_BYTES_V2: usize = 532;

// Each RequestPrepared can add one fence and one effect; terminal writes
// replace the effect. These bounds are geometry, never funded reservations.
const TRANSACTIONS: u64 = 65_536;
const TRAFFIC_AND_SEED_BYTES: u64 = 67_242_902;
const FENCE_KEY_AND_VALUE_BYTES: u64 = 24 + 741;
const COMPLETE_EFFECT_KEY_AND_VALUE_BYTES: u64 = 24 + 649;

/// Fixes all eight native main-journal limits in their canonical wire order.
pub const MAIN_LIMIT_WORDS_V2: [u64; 8] = [
    4_294_967_296,
    67_242_238,
    24,
    3,
    134_485_500,
    TRANSACTIONS,
    TRAFFIC_AND_SEED_BYTES
        + (TRANSACTIONS - 1) * (FENCE_KEY_AND_VALUE_BYTES + COMPLETE_EFFECT_KEY_AND_VALUE_BYTES),
    2 + (TRANSACTIONS - 1) * 2,
];

/// Selects one of the two closed ONLINE floor purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnlineFloorRoleV2 {
    /// Selects Controller's Nix client journal and NV index 058.
    Controller = 58,
    /// Selects the Nix owner's Controller journal and NV index 059.
    Owner = 59,
}

impl OnlineFloorRoleV2 {
    /// Returns the locally assigned NV index DATA.
    #[must_use]
    pub const fn nv_index(self) -> u32 {
        match self {
            Self::Controller => 0x0180_a058,
            Self::Owner => 0x0180_a059,
        }
    }

    /// Returns the fixed protected journal directory name.
    #[must_use]
    pub const fn directory(self) -> &'static str {
        match self {
            Self::Controller => "/var/lib/aos/sandboxd/broker-session/nix",
            Self::Owner => "/var/lib/aos/sandbox-nix/broker-session/controller",
        }
    }

    /// Returns the fixed online service unit name.
    #[must_use]
    pub const fn unit(self) -> &'static str {
        match self {
            Self::Controller => "aos-sandboxd.service",
            Self::Owner => "aos-sandbox-nixd.service",
        }
    }

    /// Computes the Name of the exact written SHA-256 extend public area.
    #[must_use]
    pub fn written_nv_name(self) -> [u8; 34] {
        let mut public = [0; 14];
        public[..4].copy_from_slice(&self.nv_index().to_be_bytes());
        public[4..6].copy_from_slice(&0x000b_u16.to_be_bytes());
        public[6..10].copy_from_slice(&0x2004_0044_u32.to_be_bytes());
        public[12..14].copy_from_slice(&32_u16.to_be_bytes());

        let mut name = [0; 34];
        name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        name[2..].copy_from_slice(&Sha256::digest(public));
        name
    }

    /// Commits the closed role, namespace and six literal route components.
    #[must_use]
    pub fn route_digest(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.nix.online-floor.route.v1\0");
        digest.update([self as u8, RecordNamespace::BrokerSessionTraffic as u8]);
        for name in [
            "Nix/NodeController",
            self.directory(),
            "session.journal",
            "tpm-floor.journal",
            "/run/aos/sandbox-nix/control.sock",
            self.unit(),
        ] {
            digest.update((name.len() as u16).to_be_bytes());
            digest.update(name.as_bytes());
        }
        digest.finalize().into()
    }
}

/// Reports noncanonical profile DATA without creating an authority owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("noncanonical ONLINE floor profile")]
pub struct OnlineFloorProfileErrorV2;

/// Supplies explicit commitments for an independently provisioned profile.
///
/// Every value is DATA. The issuer and native publisher must independently
/// authenticate these inputs; constructing a profile performs no effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnlineFloorProfileFieldsV2 {
    /// Selects the fixed client or owner purpose.
    pub role: OnlineFloorRoleV2,
    /// Identifies the local node.
    pub node: [u8; 16],
    /// Commits the selected deployment.
    pub deployment: [u8; 32],
    /// Identifies the selected endpoint.
    pub endpoint: [u8; 16],
    /// Identifies the selected Nix domain.
    pub domain: [u8; 16],
    /// Commits the complete domain definition.
    pub domain_commitment: [u8; 32],
    /// Commits the selected disclosure policy.
    pub disclosure: [u8; 32],
    /// Commits the ordered twelve-public credential set.
    pub public_set_digest: [u8; 32],
    /// Hashes the selected immutable startup profile bytes.
    pub startup_digest: [u8; 32],
    /// Identifies the stable protected journal endpoint.
    pub stable_endpoint: [u8; 32],
    /// Identifies this independently approved genesis.
    pub genesis_id: [u8; 16],
    /// Hashes the independent ONLINE issuer's ID16/public32 record.
    pub issuer_digest: [u8; 32],
    /// Hashes the role-specific TPM authorization bytes.
    pub auth_digest: [u8; 32],
    /// Names the role's provisioned SHA-256 salt key.
    pub salt_name: [u8; 34],
    /// Commits the selected immutable input/output snapshot DATA.
    pub snapshot_digest: [u8; 32],
}

/// Retains a canonical, nonauthorizing version-two ONLINE profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnlineFloorProfileV2 {
    bytes: [u8; PROFILE_BYTES_V2],
    role: OnlineFloorRoleV2,
}

impl OnlineFloorProfileV2 {
    /// Encodes explicit profile DATA using the closed route, Name and limits.
    ///
    /// # Errors
    /// Rejects zero commitments or a noncanonical SHA-256 salt Name through
    /// the same decoder used by the online consumer.
    pub fn from_fields(
        fields: OnlineFloorProfileFieldsV2,
    ) -> Result<Self, OnlineFloorProfileErrorV2> {
        let mut bytes = [0; PROFILE_BYTES_V2];
        bytes[..12].copy_from_slice(b"AOSNXF02\0\x02\0\0");
        bytes[12] = fields.role as u8;
        for (offset, value) in [
            (16, fields.node.as_slice()),
            (32, fields.deployment.as_slice()),
            (64, fields.endpoint.as_slice()),
            (80, fields.domain.as_slice()),
            (96, fields.domain_commitment.as_slice()),
            (128, fields.disclosure.as_slice()),
            (160, fields.public_set_digest.as_slice()),
            (192, fields.startup_digest.as_slice()),
            (224, fields.stable_endpoint.as_slice()),
            (256, fields.genesis_id.as_slice()),
            (272, fields.issuer_digest.as_slice()),
            (304, fields.auth_digest.as_slice()),
            (336, fields.salt_name.as_slice()),
            (500, fields.snapshot_digest.as_slice()),
        ] {
            bytes[offset..offset + value.len()].copy_from_slice(value);
        }
        bytes[370..404].copy_from_slice(&fields.role.written_nv_name());
        for (index, word) in MAIN_LIMIT_WORDS_V2.into_iter().enumerate() {
            bytes[404 + index * 8..412 + index * 8].copy_from_slice(&word.to_be_bytes());
        }
        bytes[468..500].copy_from_slice(&fields.role.route_digest());

        Self::decode(&bytes)
    }

    /// Decodes the fixed profile, including its route, written Name and limits.
    ///
    /// # Errors
    /// Rejects wrong widths, versions, reserved bytes, roles, zero commitments,
    /// invalid SHA-256 Names, foreign routes or changed main-journal limits.
    pub fn decode(bytes: &[u8]) -> Result<Self, OnlineFloorProfileErrorV2> {
        if bytes.len() != PROFILE_BYTES_V2 || bytes[..12] != *b"AOSNXF02\0\x02\0\0" {
            return Err(OnlineFloorProfileErrorV2);
        }

        let role = match bytes[12] {
            58 => OnlineFloorRoleV2::Controller,
            59 => OnlineFloorRoleV2::Owner,
            _ => return Err(OnlineFloorProfileErrorV2),
        };
        if bytes[13..16] != [0; 3]
            || [
                (16, 32),
                (32, 64),
                (64, 80),
                (80, 96),
                (96, 128),
                (128, 160),
                (160, 192),
                (192, 224),
                (224, 256),
                (256, 272),
                (272, 304),
                (304, 336),
                (468, 500),
                (500, 532),
            ]
            .iter()
            .any(|&(start, end)| bytes[start..end].iter().all(|byte| *byte == 0))
            || bytes[336..338] != [0, 0x0b]
            || bytes[338..370].iter().all(|byte| *byte == 0)
            || bytes[370..404] != role.written_nv_name()
            || bytes[468..500] != role.route_digest()
        {
            return Err(OnlineFloorProfileErrorV2);
        }

        for (index, expected) in MAIN_LIMIT_WORDS_V2.into_iter().enumerate() {
            if bytes[404 + index * 8..412 + index * 8] != expected.to_be_bytes() {
                return Err(OnlineFloorProfileErrorV2);
            }
        }

        let mut canonical = [0; PROFILE_BYTES_V2];
        canonical.copy_from_slice(bytes);
        Ok(Self {
            bytes: canonical,
            role,
        })
    }

    /// Returns the complete canonical profile DATA.
    #[must_use]
    pub const fn encode(self) -> [u8; PROFILE_BYTES_V2] {
        self.bytes
    }

    /// Returns the decoded closed role DATA.
    #[must_use]
    pub const fn role(self) -> OnlineFloorRoleV2 {
        self.role
    }

    /// Computes the profile scope commitment without authenticating its origin.
    #[must_use]
    pub fn scope(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.nix.online-floor.scope.v2\0");
        digest.update(self.bytes);
        digest.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(role: OnlineFloorRoleV2) -> OnlineFloorProfileFieldsV2 {
        let mut salt_name = [1; 34];
        salt_name[..2].copy_from_slice(&[0, 0x0b]);

        OnlineFloorProfileFieldsV2 {
            role,
            node: [1; 16],
            deployment: [1; 32],
            endpoint: [1; 16],
            domain: [1; 16],
            domain_commitment: [1; 32],
            disclosure: [1; 32],
            public_set_digest: [1; 32],
            startup_digest: [1; 32],
            stable_endpoint: [1; 32],
            genesis_id: [1; 16],
            issuer_digest: [1; 32],
            auth_digest: [1; 32],
            salt_name,
            snapshot_digest: [1; 32],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn independently_encoded_route_and_written_public_vectors_match() {
        // Vectors use independent length-prefixed route and TPMS_NV_PUBLIC
        // encoders, including the written attribute and empty authPolicy.
        for (role, route, name) in [
            (
                OnlineFloorRoleV2::Controller,
                "0812379929f11fe80c664caead011522a77f20627ec261ca8347a71e6fa24c67",
                "000b7cf918ef9cced98b541b7df684a16238bd4ea6e401a2d9a72938b869f133fd74",
            ),
            (
                OnlineFloorRoleV2::Owner,
                "c7cc0bf49a1119d1bb6120f09260de5f2832eb0524408e40d6280a05f3b0afa0",
                "000bacaa322fc0b0ae12506f8b335ee7847e0348ad12da0a69a1fef87744facac21a",
            ),
        ] {
            assert_eq!(hex(&role.route_digest()), route);
            assert_eq!(hex(&role.written_nv_name()), name);
        }
    }

    #[test]
    fn producer_and_consumer_preserve_the_closed_profile_geometry() {
        for role in [OnlineFloorRoleV2::Controller, OnlineFloorRoleV2::Owner] {
            let profile = OnlineFloorProfileV2::from_fields(fields(role)).unwrap();
            let bytes = profile.encode();

            assert_eq!(OnlineFloorProfileV2::decode(&bytes).unwrap(), profile);
            assert_eq!(profile.role(), role);
            assert_eq!(bytes[404..412], 4_294_967_296_u64.to_be_bytes());
            assert_eq!(bytes[452..460], 161_482_232_u64.to_be_bytes());
            assert_eq!(bytes[460..468], 131_072_u64.to_be_bytes());

            // Every fixed framing, Name, limit and route byte is significant.
            for offset in (0..16).chain(370..500) {
                let mut changed = bytes;
                changed[offset] ^= 0x80;
                assert!(
                    OnlineFloorProfileV2::decode(&changed).is_err(),
                    "offset {offset}"
                );
            }
            for length in [0, 12, 531, 533] {
                let mut changed = bytes.to_vec();
                changed.resize(length, 0);
                assert!(OnlineFloorProfileV2::decode(&changed).is_err());
            }
        }
    }

    #[test]
    fn absent_commitments_and_foreign_salt_names_remain_closed() {
        let profile =
            OnlineFloorProfileV2::from_fields(fields(OnlineFloorRoleV2::Controller)).unwrap();
        let bytes = profile.encode();

        for (start, end) in [
            (16, 32),
            (32, 64),
            (64, 80),
            (80, 96),
            (96, 128),
            (128, 160),
            (160, 192),
            (192, 224),
            (224, 256),
            (256, 272),
            (272, 304),
            (304, 336),
            (338, 370),
            (500, 532),
        ] {
            let mut changed = bytes;
            changed[start..end].fill(0);
            assert!(
                OnlineFloorProfileV2::decode(&changed).is_err(),
                "range {start}..{end}"
            );
        }

        let mut foreign = fields(OnlineFloorRoleV2::Controller);
        foreign.salt_name[..2].copy_from_slice(&[0, 0x0c]);
        assert!(OnlineFloorProfileV2::from_fields(foreign).is_err());

        let mut other_role = bytes;
        other_role[12] = OnlineFloorRoleV2::Owner as u8;
        assert!(OnlineFloorProfileV2::decode(&other_role).is_err());
    }
}
