//! Encodes bounded offline RAM transfer controls and object chunks.
//!
//! Offers bind a whole-world archive and its exact scoped RAM image. Requests
//! select logical coordinates within that image; the sender never exposes a
//! free-form content-store read. The stored receipt grants archive possession,
//! not live machine ownership or restore readiness.
//!
//! ```text
//! frame = U32(payload_length) | "CRUCRT01" | U8(tag) | operation:32 | body
//! integers are big-endian; strings/byte arrays are U32(length) | bytes
//! ```

use std::io::{Read, Write};

use crucible_ram::{Limits, RootRecord, Scope};
use thiserror::Error;

/// Maximum bytes in a data chunk, independently of offered credits.
pub const MAX_TRANSFER_CHUNK_BYTES: u32 = 64 * 1024;
/// Maximum canonical bytes in any transferred RAM object.
pub const MAX_TRANSFER_OBJECT_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum bytes in one control or data frame.
pub const MAX_TRANSFER_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"CRUCRT01";

/// Negotiated upper bounds for an offline RAM transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamTransferLimits {
    /// Maximum object requests, including repeated logical occurrences.
    pub objects: u64,
    /// Maximum canonical object bytes received during discovery.
    pub bytes: u64,
    /// Maximum bytes permitted in each object chunk.
    pub chunk_bytes: u32,
}

/// A source-bound complete RAM image belonging to a whole-world archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamTransferOffer {
    /// Authenticated whole-world checkpoint storage identity.
    pub whole_world_root: String,
    /// Complete RAM root storage identity named by that checkpoint.
    pub ram_root: String,
    /// Canonical exact-scope logical inventory and region roots.
    pub root_record: Vec<u8>,
    /// Operational destination identity, excluded from logical RAM identity.
    pub destination: String,
    /// Required durable destination placement count.
    pub durable_placements: u16,
    /// Receiver-controlled operation ceilings.
    pub limits: RamTransferLimits,
}

/// A canonical metadata position selected through the offered root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RamTransferNodeCoordinate {
    /// The offered complete RAM root's canonical storage envelope.
    Root,
    /// An aligned binary catalog subtree within a selected logical region.
    Catalog {
        /// Stable UTF-8 inventory identifier.
        region_id: String,
        /// First logical page covered by this subtree.
        first_page: u64,
        /// Binary subtree height.
        height: u32,
    },
}

/// A closed control vocabulary for bounded archive transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RamTransferControl {
    /// Establishes the source image and destination resource contract.
    Offer(RamTransferOffer),
    /// Requests one authenticated metadata object by logical position.
    WantNode {
        /// Source-root-bound metadata coordinate.
        coordinate: RamTransferNodeCoordinate,
        /// Expected storage identity derived from authenticated parent metadata.
        object: String,
    },
    /// Requests one real page object by logical position.
    WantObject {
        /// Stable region inventory identifier.
        region_id: String,
        /// Real logical page position, excluding padding.
        page_index: u64,
        /// Expected page object identity derived from its leaf catalog.
        object: String,
    },
    /// Carries an ordered bounded slice of one requested canonical object.
    ObjectChunk {
        /// Requested canonical storage identity.
        object: String,
        /// Declared complete canonical length.
        length: u64,
        /// Zero-based offset of this slice.
        offset: u64,
        /// Bounded plaintext object bytes.
        bytes: Vec<u8>,
        /// Whether this slice completes exactly the declared object length.
        last: bool,
    },
    /// Grants capacity for the next data chunk while preserving control service.
    Credit {
        /// Requested object whose next slice is authorized.
        object: String,
        /// Absolute next offset, making repeated credits idempotent.
        offset: u64,
        /// Maximum bytes in the next permitted chunk.
        bytes: u32,
    },
    /// Acknowledges complete durable local RAM possession under a live lease.
    ClosureStored {
        /// Exact complete RAM root independently retained at the destination.
        ram_root: String,
    },
    /// Stops new requests and asks the peer to dispose active work safely.
    Cancel,
    /// Acknowledges that active chunk ownership has been disposed.
    Canceled,
    /// Reports a fail-closed terminal protocol or integrity outcome.
    Fail {
        /// Stable failure classification supplied by the operational owner.
        code: u16,
    },
}

/// One operation-bound offline transfer message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamTransferMessage {
    /// Destination- and archive-bound operation identity.
    pub operation: [u8; 32],
    /// Closed portable control body.
    pub control: RamTransferControl,
}

/// Error while validating, encoding, or reading a transfer frame.
#[derive(Debug, Error)]
pub enum RamTransferCodecError {
    /// A control body, identity, or coordinate was malformed.
    #[error("invalid RAM transfer control")]
    Invalid,
    /// A declared resource dimension exceeded the wire edition's bounds.
    #[error("RAM transfer control exceeds {0}")]
    Limit(&'static str),
    /// Transport I/O failed before a complete frame became available.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl RamTransferMessage {
    /// Encodes one validated bounded message, including its length prefix.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bodies, identities, limits, or excessive size.
    pub fn encode(&self) -> Result<Vec<u8>, RamTransferCodecError> {
        validate(&self.control)?;
        let mut body = Vec::new();
        body.extend_from_slice(MAGIC);
        body.push(match self.control {
            RamTransferControl::Offer(_) => 1,
            RamTransferControl::WantNode { .. } => 2,
            RamTransferControl::WantObject { .. } => 3,
            RamTransferControl::ObjectChunk { .. } => 4,
            RamTransferControl::Credit { .. } => 5,
            RamTransferControl::ClosureStored { .. } => 6,
            RamTransferControl::Cancel => 7,
            RamTransferControl::Canceled => 8,
            RamTransferControl::Fail { .. } => 9,
        });
        body.extend_from_slice(&self.operation);
        match &self.control {
            RamTransferControl::Offer(offer) => {
                put_bytes(&mut body, offer.whole_world_root.as_bytes())?;
                put_bytes(&mut body, offer.ram_root.as_bytes())?;
                put_bytes(&mut body, &offer.root_record)?;
                put_bytes(&mut body, offer.destination.as_bytes())?;
                body.extend_from_slice(&offer.durable_placements.to_be_bytes());
                body.extend_from_slice(&offer.limits.objects.to_be_bytes());
                body.extend_from_slice(&offer.limits.bytes.to_be_bytes());
                body.extend_from_slice(&offer.limits.chunk_bytes.to_be_bytes());
            }
            RamTransferControl::WantNode { coordinate, object } => {
                match coordinate {
                    RamTransferNodeCoordinate::Root => body.push(0),
                    RamTransferNodeCoordinate::Catalog {
                        region_id,
                        first_page,
                        height,
                    } => {
                        body.push(1);
                        put_bytes(&mut body, region_id.as_bytes())?;
                        body.extend_from_slice(&first_page.to_be_bytes());
                        body.extend_from_slice(&height.to_be_bytes());
                    }
                }
                put_bytes(&mut body, object.as_bytes())?;
            }
            RamTransferControl::WantObject {
                region_id,
                page_index,
                object,
            } => {
                put_bytes(&mut body, region_id.as_bytes())?;
                body.extend_from_slice(&page_index.to_be_bytes());
                put_bytes(&mut body, object.as_bytes())?;
            }
            RamTransferControl::ObjectChunk {
                object,
                length,
                offset,
                bytes,
                last,
            } => {
                put_bytes(&mut body, object.as_bytes())?;
                body.extend_from_slice(&length.to_be_bytes());
                body.extend_from_slice(&offset.to_be_bytes());
                body.push(u8::from(*last));
                put_bytes(&mut body, bytes)?;
            }
            RamTransferControl::Credit {
                object,
                offset,
                bytes,
            } => {
                put_bytes(&mut body, object.as_bytes())?;
                body.extend_from_slice(&offset.to_be_bytes());
                body.extend_from_slice(&bytes.to_be_bytes());
            }
            RamTransferControl::ClosureStored { ram_root } => {
                put_bytes(&mut body, ram_root.as_bytes())?
            }
            RamTransferControl::Fail { code } => body.extend_from_slice(&code.to_be_bytes()),
            RamTransferControl::Cancel | RamTransferControl::Canceled => {}
        }
        if body.len() > MAX_TRANSFER_FRAME_BYTES {
            return Err(RamTransferCodecError::Limit("frame bytes"));
        }
        let mut frame = Vec::with_capacity(body.len() + 4);
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Decodes one exact frame without accepting trailing or truncated bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed framing, unknown tags, or exceeded bounds.
    pub fn decode(frame: &[u8]) -> Result<Self, RamTransferCodecError> {
        let mut reader = Decoder {
            bytes: frame,
            offset: 0,
        };
        let length = reader.u32()? as usize;
        if length > MAX_TRANSFER_FRAME_BYTES {
            return Err(RamTransferCodecError::Limit("frame bytes"));
        }
        if reader.remaining() != length || reader.take(8)? != MAGIC {
            return Err(RamTransferCodecError::Invalid);
        }
        let tag = reader.byte()?;
        let mut operation = [0_u8; 32];
        operation.copy_from_slice(reader.take(32)?);
        let control = match tag {
            1 => RamTransferControl::Offer(RamTransferOffer {
                whole_world_root: reader.string(128)?,
                ram_root: reader.string(128)?,
                root_record: reader.blob(3 * 1024 * 1024)?,
                destination: reader.string(1024)?,
                durable_placements: reader.u16()?,
                limits: RamTransferLimits {
                    objects: reader.u64()?,
                    bytes: reader.u64()?,
                    chunk_bytes: reader.u32()?,
                },
            }),
            2 => {
                let coordinate = match reader.byte()? {
                    0 => RamTransferNodeCoordinate::Root,
                    1 => RamTransferNodeCoordinate::Catalog {
                        region_id: reader.string(255)?,
                        first_page: reader.u64()?,
                        height: reader.u32()?,
                    },
                    _ => return Err(RamTransferCodecError::Invalid),
                };
                RamTransferControl::WantNode {
                    coordinate,
                    object: reader.string(128)?,
                }
            }
            3 => RamTransferControl::WantObject {
                region_id: reader.string(255)?,
                page_index: reader.u64()?,
                object: reader.string(128)?,
            },
            4 => RamTransferControl::ObjectChunk {
                object: reader.string(128)?,
                length: reader.u64()?,
                offset: reader.u64()?,
                last: match reader.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(RamTransferCodecError::Invalid),
                },
                bytes: reader.blob(MAX_TRANSFER_CHUNK_BYTES as usize)?,
            },
            5 => RamTransferControl::Credit {
                object: reader.string(128)?,
                offset: reader.u64()?,
                bytes: reader.u32()?,
            },
            6 => RamTransferControl::ClosureStored {
                ram_root: reader.string(128)?,
            },
            7 => RamTransferControl::Cancel,
            8 => RamTransferControl::Canceled,
            9 => RamTransferControl::Fail {
                code: reader.u16()?,
            },
            _ => return Err(RamTransferCodecError::Invalid),
        };
        if reader.remaining() != 0 {
            return Err(RamTransferCodecError::Invalid);
        }
        validate(&control)?;
        Ok(Self { operation, control })
    }

    /// Reads one bounded frame from a transport managed by the operation owner.
    ///
    /// # Errors
    ///
    /// Returns I/O, malformed framing, or resource limit errors.
    pub fn read(reader: &mut dyn Read) -> Result<Self, RamTransferCodecError> {
        let mut prefix = [0_u8; 4];
        reader.read_exact(&mut prefix)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_TRANSFER_FRAME_BYTES {
            return Err(RamTransferCodecError::Limit("frame bytes"));
        }
        let mut frame = vec![0_u8; length + 4];
        frame[..4].copy_from_slice(&prefix);
        reader.read_exact(&mut frame[4..])?;
        Self::decode(&frame)
    }

    /// Writes one exact validated frame to the operation's transport.
    ///
    /// # Errors
    ///
    /// Returns validation, resource ceiling, or transport I/O errors.
    pub fn write(&self, writer: &mut dyn Write) -> Result<(), RamTransferCodecError> {
        writer.write_all(&self.encode()?)?;
        writer.flush()?;
        Ok(())
    }
}

fn validate(control: &RamTransferControl) -> Result<(), RamTransferCodecError> {
    match control {
        RamTransferControl::Offer(offer) => {
            content_id(&offer.whole_world_root, &["exact-manifest.6."])?;
            content_id(&offer.ram_root, &["exact-manifest.1."])?;
            text(&offer.destination, 1024)?;
            if offer.durable_placements == 0
                || offer.durable_placements > 256
                || offer.limits.objects == 0
                || offer.limits.bytes == 0
            {
                return Err(RamTransferCodecError::Invalid);
            }
            credit(offer.limits.chunk_bytes)?;
            let record = RootRecord::decode(&offer.root_record, Limits::default())
                .map_err(|_| RamTransferCodecError::Invalid)?;
            if record.scope() != Scope::Exact || record.encode() != offer.root_record {
                return Err(RamTransferCodecError::Invalid);
            }
        }
        RamTransferControl::WantNode { coordinate, object } => match coordinate {
            RamTransferNodeCoordinate::Root => content_id(object, &["exact-manifest.1."])?,
            RamTransferNodeCoordinate::Catalog {
                region_id,
                first_page,
                height,
            } => {
                text(region_id, 255)?;
                if *height > 52 || *first_page >= 1_u64 << 52 || first_page % (1_u64 << height) != 0
                {
                    return Err(RamTransferCodecError::Invalid);
                }
                content_id(object, &["ram-tree.1."])?;
            }
        },
        RamTransferControl::WantObject {
            region_id,
            page_index,
            object,
        } => {
            text(region_id, 255)?;
            if *page_index >= 1_u64 << 52 {
                return Err(RamTransferCodecError::Invalid);
            }
            content_id(object, &["ram-extent.1."])?;
        }
        RamTransferControl::ObjectChunk {
            object,
            length,
            offset,
            bytes,
            last,
        } => {
            content_id(
                object,
                &["exact-manifest.1.", "ram-tree.1.", "ram-extent.1."],
            )?;
            if *length == 0
                || *length > MAX_TRANSFER_OBJECT_BYTES
                || bytes.is_empty()
                || bytes.len() > MAX_TRANSFER_CHUNK_BYTES as usize
            {
                return Err(RamTransferCodecError::Limit("object chunk"));
            }
            let end = offset
                .checked_add(bytes.len() as u64)
                .ok_or(RamTransferCodecError::Invalid)?;
            if end > *length || *last != (end == *length) {
                return Err(RamTransferCodecError::Invalid);
            }
        }
        RamTransferControl::Credit {
            object,
            offset,
            bytes,
        } => {
            content_id(
                object,
                &["exact-manifest.1.", "ram-tree.1.", "ram-extent.1."],
            )?;
            if *offset >= MAX_TRANSFER_OBJECT_BYTES {
                return Err(RamTransferCodecError::Invalid);
            }
            credit(*bytes)?;
        }
        RamTransferControl::ClosureStored { ram_root } => {
            content_id(ram_root, &["exact-manifest.1."])?
        }
        RamTransferControl::Cancel
        | RamTransferControl::Canceled
        | RamTransferControl::Fail { .. } => {}
    }
    Ok(())
}

fn credit(bytes: u32) -> Result<(), RamTransferCodecError> {
    if bytes == 0 || bytes > MAX_TRANSFER_CHUNK_BYTES {
        return Err(RamTransferCodecError::Limit("chunk credit"));
    }
    Ok(())
}

fn text(value: &str, maximum: usize) -> Result<(), RamTransferCodecError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(RamTransferCodecError::Invalid);
    }
    Ok(())
}

fn content_id(value: &str, prefixes: &[&str]) -> Result<(), RamTransferCodecError> {
    let digest = prefixes
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
        .ok_or(RamTransferCodecError::Invalid)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RamTransferCodecError::Invalid);
    }
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RamTransferCodecError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| RamTransferCodecError::Limit("field bytes"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], RamTransferCodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RamTransferCodecError::Invalid)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(RamTransferCodecError::Invalid)?;
        self.offset = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, RamTransferCodecError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, RamTransferCodecError> {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(bytes))
    }
    fn u32(&mut self) -> Result<u32, RamTransferCodecError> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(bytes))
    }
    fn u64(&mut self) -> Result<u64, RamTransferCodecError> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }
    fn blob(&mut self, maximum: usize) -> Result<Vec<u8>, RamTransferCodecError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(RamTransferCodecError::Limit("field bytes"));
        }
        Ok(self.take(length)?.to_vec())
    }
    fn string(&mut self, maximum: usize) -> Result<String, RamTransferCodecError> {
        String::from_utf8(self.blob(maximum)?).map_err(|_| RamTransferCodecError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_ram::{MetadataBudget, RegionClass, RegionDescriptor, RegionTree, Topology};

    fn id(kind: &str, version: u32) -> String {
        format!("{kind}.{version}.{}", "ab".repeat(32))
    }

    fn offer(scope: Scope) -> RamTransferOffer {
        let region = RegionDescriptor::new("main", RegionClass::MutableMain, 4097)
            .unwrap_or_else(|error| panic!("fixture RAM region: {error}"));
        let topology = Topology::new(vec![region], Limits::default())
            .unwrap_or_else(|error| panic!("fixture RAM topology: {error}"));
        let tree = RegionTree::zeroed(4097, &MetadataBudget::new(64 * 1024))
            .unwrap_or_else(|error| panic!("fixture RAM tree: {error}"));
        let record = RootRecord::new(topology, scope, vec![tree.digest()])
            .unwrap_or_else(|error| panic!("fixture RAM root: {error}"));
        RamTransferOffer {
            whole_world_root: id("exact-manifest", 6),
            ram_root: id("exact-manifest", 1),
            root_record: record.encode(),
            destination: "destination".into(),
            durable_placements: 1,
            limits: RamTransferLimits {
                objects: 1_000,
                bytes: 1_000_000,
                chunk_bytes: 64,
            },
        }
    }

    #[test]
    fn archive_controls_round_trip_without_accepting_trailing_or_truncated_frames() {
        let controls = vec![
            RamTransferControl::Offer(offer(Scope::Exact)),
            RamTransferControl::WantNode {
                coordinate: RamTransferNodeCoordinate::Root,
                object: id("exact-manifest", 1),
            },
            RamTransferControl::WantNode {
                coordinate: RamTransferNodeCoordinate::Catalog {
                    region_id: "main".into(),
                    first_page: 0,
                    height: 1,
                },
                object: id("ram-tree", 1),
            },
            RamTransferControl::WantObject {
                region_id: "main".into(),
                page_index: 1,
                object: id("ram-extent", 1),
            },
            RamTransferControl::ObjectChunk {
                object: id("ram-tree", 1),
                length: 3,
                offset: 0,
                bytes: vec![1, 2, 3],
                last: true,
            },
            RamTransferControl::Credit {
                object: id("ram-tree", 1),
                offset: 3,
                bytes: 64,
            },
            RamTransferControl::ClosureStored {
                ram_root: id("exact-manifest", 1),
            },
            RamTransferControl::Cancel,
            RamTransferControl::Canceled,
            RamTransferControl::Fail { code: 7 },
        ];
        for control in controls {
            let message = RamTransferMessage {
                operation: [7; 32],
                control,
            };
            let bytes = message
                .encode()
                .unwrap_or_else(|error| panic!("encode transfer fixture: {error}"));
            assert_eq!(
                RamTransferMessage::decode(&bytes)
                    .unwrap_or_else(|error| panic!("decode transfer fixture: {error}")),
                message
            );
            for length in 0..bytes.len() {
                assert!(RamTransferMessage::decode(&bytes[..length]).is_err());
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(RamTransferMessage::decode(&trailing).is_err());
        }
    }

    #[test]
    fn transfer_edition_rejects_weak_scope_noncanonical_ids_and_unbounded_chunks() {
        let controls = [
            RamTransferControl::Offer(offer(Scope::Execution)),
            RamTransferControl::Credit {
                object: id("ram-tree", 1),
                offset: 0,
                bytes: 0,
            },
            RamTransferControl::WantNode {
                coordinate: RamTransferNodeCoordinate::Catalog {
                    region_id: "main".into(),
                    first_page: 1,
                    height: 1,
                },
                object: id("ram-tree", 1),
            },
            RamTransferControl::WantObject {
                region_id: "main".into(),
                page_index: 0,
                object: id("ram-extent", 1).to_uppercase(),
            },
            RamTransferControl::ObjectChunk {
                object: id("ram-extent", 1),
                length: 2,
                offset: 0,
                bytes: vec![1],
                last: true,
            },
            RamTransferControl::ObjectChunk {
                object: id("ram-tree", 1),
                length: MAX_TRANSFER_OBJECT_BYTES + 1,
                offset: 0,
                bytes: vec![1],
                last: false,
            },
        ];
        for control in controls {
            assert!(
                RamTransferMessage {
                    operation: [1; 32],
                    control
                }
                .encode()
                .is_err()
            );
        }
        assert!(
            RamTransferMessage::decode(&(MAX_TRANSFER_FRAME_BYTES as u32 + 1).to_be_bytes())
                .is_err()
        );
    }
}
