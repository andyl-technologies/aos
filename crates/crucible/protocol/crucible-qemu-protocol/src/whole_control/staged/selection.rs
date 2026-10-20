//! Complete constructor selection of staged limits and logical queue names.
//!
//! This body is retained in the original sealed setup descriptor. Logical
//! names select no physical queue: the GPL constructor independently joins
//! every selected role to its original source getter and registered handles.
//!
//! ```text
//! CWHLSEL\0, format3:u32, extent:u32, Profile168,
//! role_count:u32, reserved0:u32, launch_extent:u32, launch_version:u32,
//! complete_launch[L], role_names[count]
//! role_names: role:u16, reserved0:u16, node/port/lane_bytes:u16,
//!             reserved0:u16, node[N], port[P], lane[L]
//! Integers are big endian; at most six distinct named roles are retained.
//! ```

use super::{
    StagedControlProfile,
    launch::{LAUNCH_SELECTION_MAX_BYTES, LaunchSelection},
    launch2::LaunchSelection2,
};
use crate::whole_control::{WholeControlError, inventory::WholeQueueRole, put_u32, read_u32};

/// Bounds every byte of a complete constructor selection before installation.
pub const WHOLE_SELECTION_MAX_BYTES: usize = 200 + LAUNCH_SELECTION_MAX_BYTES + 6 * (12 + 3 * 128);

/// Borrows one original logical role name without physical source authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalQueueRole<'a> {
    /// Selects an actually implemented packet, block or read-only 9p operation.
    pub role: WholeQueueRole,
    /// Names the original host logical node under the advertised ASCII profile.
    pub node: &'a str,
    /// Names the original host port.
    pub port: &'a str,
    /// Names the original host lane.
    pub lane: &'a str,
}

/// Owns every original constructor byte and its validated staged profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WholeConstructorSelection {
    profile: StagedControlProfile,
    body: Box<[u8]>,
}

impl WholeConstructorSelection {
    /// Builds a bounded original constructor selection before publication.
    ///
    /// # Errors
    /// Rejects malformed profile, duplicate or unsupported roles, invalid ASCII
    /// names, mixed nodes, overflowing extents or allocation failure.
    pub fn new(
        profile: StagedControlProfile,
        launch: &LaunchSelection<'_>,
        roles: &[LogicalQueueRole<'_>],
    ) -> Result<Self, WholeControlError> {
        Self::encode_original(profile, 1, launch.body(), roles)
    }

    /// Builds an explicit version-two launch selection before publication.
    ///
    /// # Errors
    /// Rejects malformed profiles, role names, duplicate roles, overflowing
    /// complete constructor extents or allocation failure.
    pub fn new2(
        profile: StagedControlProfile,
        launch: &LaunchSelection2<'_>,
        roles: &[LogicalQueueRole<'_>],
    ) -> Result<Self, WholeControlError> {
        Self::encode_original(profile, 2, launch.body(), roles)
    }

    fn encode_original(
        profile: StagedControlProfile,
        launch_version: u32,
        launch: &[u8],
        roles: &[LogicalQueueRole<'_>],
    ) -> Result<Self, WholeControlError> {
        profile.validate()?;
        if !(1..=6).contains(&roles.len()) {
            return Err(WholeControlError::Body);
        }
        let extent = roles
            .iter()
            .try_fold(200 + launch.len(), |total, role| {
                [role.node, role.port, role.lane]
                    .into_iter()
                    .try_fold(total.checked_add(12)?, |sum, id| sum.checked_add(id.len()))
            })
            .ok_or(WholeControlError::Budget)?;
        if extent > WHOLE_SELECTION_MAX_BYTES {
            return Err(WholeControlError::Body);
        }
        let mut body = Vec::new();
        body.try_reserve_exact(extent)
            .map_err(|_| WholeControlError::Budget)?;
        body.resize(extent, 0);
        body[..8].copy_from_slice(b"CWHLSEL\0");
        put_u32(&mut body, 8, 3);
        put_u32(&mut body, 12, extent as u32);
        body[16..184].copy_from_slice(&profile.encode()?);
        put_u32(&mut body, 184, roles.len() as u32);
        put_u32(&mut body, 192, launch.len() as u32);
        put_u32(&mut body, 196, launch_version);
        body[200..200 + launch.len()].copy_from_slice(launch);
        let mut offset = 200 + launch.len();
        for role in roles {
            let ids = [role.node, role.port, role.lane];
            if ids.iter().any(|id| !(1..=128).contains(&id.len())) {
                return Err(WholeControlError::Body);
            }
            body[offset..offset + 2].copy_from_slice(&(role.role as u16).to_be_bytes());
            for (index, id) in ids.iter().enumerate() {
                body[offset + 4 + 2 * index..offset + 6 + 2 * index]
                    .copy_from_slice(&(id.len() as u16).to_be_bytes());
            }
            offset += 12;
            for id in ids {
                body[offset..offset + id.len()].copy_from_slice(id.as_bytes());
                offset += id.len();
            }
        }
        Self::from_body(body.into_boxed_slice())
    }

    /// Validates and retains the full original constructor body without replacing it.
    ///
    /// # Errors
    /// Rejects malformed header, profile, reserved fields, names or role roster.
    pub fn from_body(body: Box<[u8]>) -> Result<Self, WholeControlError> {
        if !(200..=WHOLE_SELECTION_MAX_BYTES).contains(&body.len())
            || body[..8] != *b"CWHLSEL\0"
            || read_u32(&body, 8) != 3
            || read_u32(&body, 12) as usize != body.len()
            || !(1..=6).contains(&read_u32(&body, 184))
            || read_u32(&body, 188) != 0
            || !matches!(read_u32(&body, 196), 1 | 2)
        {
            return Err(WholeControlError::Body);
        }
        let profile = StagedControlProfile::decode(&body[16..184])?;
        let launch_end = 200usize
            .checked_add(read_u32(&body, 192) as usize)
            .filter(|end| *end <= body.len())
            .ok_or(WholeControlError::Body)?;
        match read_u32(&body, 196) {
            1 => {
                LaunchSelection::decode(&body[200..launch_end])?;
            }
            2 => {
                LaunchSelection2::decode(&body[200..launch_end])?;
                profile.validate_ready_exchange_capacity()?;
            }
            _ => return Err(WholeControlError::Body),
        }
        let mut remaining = &body[launch_end..];
        let mut mask = 0u8;
        let mut node = None;
        for _ in 0..read_u32(&body, 184) {
            let (role, used) = decode_role(remaining)?;
            let bit = 1 << role.role as u16;
            if mask & bit != 0 || node.is_some_and(|node| node != role.node) {
                return Err(WholeControlError::Body);
            }
            mask |= bit;
            node = Some(role.node);
            remaining = &remaining[used..];
        }
        if !remaining.is_empty() {
            return Err(WholeControlError::Body);
        }
        Ok(Self { profile, body })
    }

    /// Borrows the complete immutable original constructor bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Borrows the separately bounded original stage and compute profile.
    pub const fn profile(&self) -> &StagedControlProfile {
        &self.profile
    }

    /// Borrows complete original launch provenance retained before constructor effects.
    ///
    /// # Errors
    /// Rejects invalid retained launch bytes. Native source ownership and original
    /// descriptor enrollment remain independent of these portable correlations.
    pub fn launch(&self) -> Result<LaunchSelection<'_>, WholeControlError> {
        if self.launch_version() != 1 {
            return Err(WholeControlError::Body);
        }
        let end = 200 + read_u32(&self.body, 192) as usize;
        LaunchSelection::decode(&self.body[200..end])
    }

    /// Returns the explicitly retained launch format version.
    pub fn launch_version(&self) -> u32 {
        read_u32(&self.body, 196)
    }

    /// Borrows complete version-two provenance without changing its original bytes.
    ///
    /// # Errors
    /// Rejects another launch version or malformed retained launch bytes. Native
    /// source enrollment remains independent of these portable correlations.
    pub fn launch2(&self) -> Result<LaunchSelection2<'_>, WholeControlError> {
        if self.launch_version() != 2 {
            return Err(WholeControlError::Body);
        }
        let end = 200 + read_u32(&self.body, 192) as usize;
        LaunchSelection2::decode(&self.body[200..end])
    }

    /// Iterates original logical names without constructing a physical roster.
    pub fn roles(&self) -> LogicalQueueRoles<'_> {
        LogicalQueueRoles {
            remaining: &self.body[200 + read_u32(&self.body, 192) as usize..],
        }
    }
}

/// Iterates a complete previously validated logical role roster.
pub struct LogicalQueueRoles<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for LogicalQueueRoles<'a> {
    type Item = LogicalQueueRole<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let (role, used) = decode_role(self.remaining).ok()?;
        self.remaining = &self.remaining[used..];
        Some(role)
    }
}

fn decode_role(body: &[u8]) -> Result<(LogicalQueueRole<'_>, usize), WholeControlError> {
    if body.len() < 12 || body[2..4] != [0; 2] || body[10..12] != [0; 2] {
        return Err(WholeControlError::Body);
    }
    let lengths =
        [4, 6, 8].map(|offset| u16::from_be_bytes([body[offset], body[offset + 1]]) as usize);
    let extent = lengths
        .into_iter()
        .try_fold(12usize, |sum, length| sum.checked_add(length))
        .ok_or(WholeControlError::Body)?;
    if extent > body.len() || lengths.iter().any(|length| !(1..=128).contains(length)) {
        return Err(WholeControlError::Body);
    }
    let role = match u16::from_be_bytes([body[0], body[1]]) {
        1 => WholeQueueRole::PacketDelivery,
        2 => WholeQueueRole::BlockCompletion,
        3 => WholeQueueRole::ReadonlyNinePCompletion,
        4 => WholeQueueRole::PacketPublication,
        5 => WholeQueueRole::BlockRequest,
        6 => WholeQueueRole::ReadonlyNinePRequest,
        _ => return Err(WholeControlError::Body),
    };
    let mut offset = 12;
    let mut id = |length| {
        let value = std::str::from_utf8(&body[offset..offset + length])
            .map_err(|_| WholeControlError::Body)?;
        offset += length;
        let mut bytes = value.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err(WholeControlError::Body);
        }
        Ok(value)
    };
    Ok((
        LogicalQueueRole {
            role,
            node: id(lengths[0])?,
            port: id(lengths[1])?,
            lane: id(lengths[2])?,
        },
        extent,
    ))
}
