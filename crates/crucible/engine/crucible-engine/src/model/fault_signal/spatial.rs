//! Canonical normalized spatial fields used by the signal evaluator.
//!
//! Geographic and vendor formats are normalized before admission. Runtime
//! evaluation consumes only integer Cartesian coordinates, exact rationals,
//! closed interpolation policies, and content-addressed tile references.

use std::error::Error;
use std::fmt;

use crate::model::DagStore;

use super::*;

/// Spatial artifact codec semantic version.
pub const SPATIAL_CODEC_VERSION: u16 = 1;
/// Hard maximum values, samples, zones, or profile points in one artifact.
pub const HARD_SPATIAL_ITEMS: usize = 4_194_304;
/// Hard maximum tile references in one manifest.
pub const HARD_SPATIAL_TILES: usize = 262_144;
const MAGIC: &[u8; 8] = b"CRSPAT01";

/// One named position/value sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpatialSample {
    /// Integer local Cartesian position in millimetres.
    pub position_mm: [i64; 3],
    /// Typed sample value.
    pub value: SignalValue,
}

/// One explicit line, triangle, or tetrahedron in a point-set interpolation mesh.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpatialSimplex {
    /// Two, three, or four sample indexes in ascending order.
    pub vertices: Vec<u32>,
}

/// One half-space inequality `a*x + b*y + c*z <= offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpatialPlane {
    /// X coefficient.
    pub a: i64,
    /// Y coefficient.
    pub b: i64,
    /// Z coefficient.
    pub c: i64,
    /// Inclusive half-space offset.
    pub offset: i128,
}

/// One convex cell; a zone may contain multiple cells to represent non-convex geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpatialConvexCell {
    /// Nonempty intersection of half spaces.
    pub planes: Vec<SpatialPlane>,
}

/// One named, prioritized polygonal or polyhedral zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpatialZone {
    /// Variant returned for membership.
    pub id: SignalId,
    /// Larger priority wins before stable ID tie-breaking.
    pub priority: i64,
    /// Union of convex cells.
    pub cells: Vec<SpatialConvexCell>,
}

/// One regular-grid tile reference and its exact closed bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpatialTileReference {
    /// Inclusive tile origin.
    pub minimum_mm: [i64; 3],
    /// Exclusive tile end.
    pub maximum_mm: [i64; 3],
    /// Content address of a [`SpatialArtifactKind::RegularGrid`] artifact.
    pub content: ContentHash,
}

/// One path profile sample at a declared path vertex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpatialPathPoint {
    /// Strictly increasing cumulative distance in millimetres.
    pub distance_mm: u64,
    /// Path vertex position.
    pub position_mm: [i64; 3],
    /// Typed profile value.
    pub value: SignalValue,
}

/// Closed normalized spatial payload variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpatialArtifactKind {
    /// Sparse named samples.
    PointSet {
        /// Samples in lexicographic position order.
        samples: Vec<SpatialSample>,
        /// Interpolation cells in canonical vertex order; the first containing
        /// cell wins on a shared boundary.
        simplices: Vec<SpatialSimplex>,
    },
    /// Dense row-major grid, X varying fastest, then Y, then Z.
    RegularGrid {
        /// Grid origin.
        origin_mm: [i64; 3],
        /// Positive cell spacing.
        cell_size_mm: [u64; 3],
        /// Positive dimensions.
        dimensions: [u32; 3],
        /// Exact row-major values.
        values: Vec<SignalValue>,
    },
    /// Seekable manifest of non-overlapping regular-grid tiles.
    TiledGrid {
        /// Tile references in increasing bound order.
        tiles: Vec<SpatialTileReference>,
    },
    /// Prioritized union-of-convex-cells zone map.
    ZoneMap {
        /// Variant returned outside every zone.
        outside: SignalId,
        /// Zones in canonical priority/ID order.
        zones: Vec<SpatialZone>,
    },
    /// Polyline and quantity profile indexed along the same vertices.
    PathProfile {
        /// Stable path identity.
        path: SignalId,
        /// Ordered vertices/profile values.
        points: Vec<SpatialPathPoint>,
    },
    /// Calibrated transmitter distance lookup plus exact environment weights.
    TransmitterLookup {
        /// Stable propagation model identity.
        model: SignalId,
        /// Transmitter position.
        transmitter_mm: [i64; 3],
        /// Strictly increasing distance/value lookup.
        distance_values: Vec<(u64, SignalValue)>,
        /// Canonically ordered receiver-orientation corrections.
        orientation_values: Vec<([i64; 3], SignalValue)>,
        /// One exact additive coefficient per environmental input.
        environment_coefficients: Vec<ExactRatio>,
    },
}

/// Validated content-addressed spatial artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedSpatialArtifact {
    frame: SignalId,
    shape: SignalShape,
    kind: SpatialArtifactKind,
    content: ContentHash,
}

impl NormalizedSpatialArtifact {
    /// Validates and content-addresses one normalized spatial artifact.
    ///
    /// # Errors
    ///
    /// Returns [`SpatialArtifactError`] when geometry, ordering, counts,
    /// dimensions, shapes, bounds, or parameters violate the closed contract.
    pub fn new(
        frame: SignalId,
        shape: SignalShape,
        kind: SpatialArtifactKind,
    ) -> Result<Self, SpatialArtifactError> {
        shape.validate().map_err(SpatialArtifactError::Program)?;
        validate_kind(&shape, &kind)?;
        let mut value = Self {
            frame,
            shape,
            kind,
            content: ContentHash::default(),
        };
        value.content = ContentHash::from_bytes(&value.encode());
        Ok(value)
    }

    /// Returns the coordinate frame.
    #[must_use]
    pub const fn frame(&self) -> &SignalId {
        &self.frame
    }

    /// Returns the static value shape.
    #[must_use]
    pub const fn shape(&self) -> &SignalShape {
        &self.shape
    }

    /// Returns the closed normalized payload.
    #[must_use]
    pub const fn kind(&self) -> &SpatialArtifactKind {
        &self.kind
    }

    /// Returns the canonical content address.
    #[must_use]
    pub const fn content(&self) -> ContentHash {
        self.content
    }

    /// Encodes the portable canonical big-endian representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = SpatialWriter::default();
        writer.bytes.extend_from_slice(MAGIC);
        writer.u16(SPATIAL_CODEC_VERSION);
        writer.text(self.frame.as_str());
        writer.blob(&encode_signal_shape(&self.shape).unwrap_or_default());
        match &self.kind {
            SpatialArtifactKind::PointSet { samples, simplices } => {
                writer.byte(0);
                writer.count(samples.len());
                for sample in samples {
                    writer.position(sample.position_mm);
                    writer.value(&sample.value);
                }
                writer.count(simplices.len());
                for simplex in simplices {
                    writer.count(simplex.vertices.len());
                    for vertex in &simplex.vertices {
                        writer.u32(*vertex);
                    }
                }
            }
            SpatialArtifactKind::RegularGrid {
                origin_mm,
                cell_size_mm,
                dimensions,
                values,
            } => {
                writer.byte(1);
                writer.position(*origin_mm);
                writer.u64_array(*cell_size_mm);
                writer.u32_array(*dimensions);
                writer.count(values.len());
                for value in values {
                    writer.value(value);
                }
            }
            SpatialArtifactKind::TiledGrid { tiles } => {
                writer.byte(2);
                writer.count(tiles.len());
                for tile in tiles {
                    writer.position(tile.minimum_mm);
                    writer.position(tile.maximum_mm);
                    writer.bytes.extend_from_slice(&tile.content.bytes);
                }
            }
            SpatialArtifactKind::ZoneMap { outside, zones } => {
                writer.byte(3);
                writer.text(outside.as_str());
                writer.count(zones.len());
                for zone in zones {
                    writer.text(zone.id.as_str());
                    writer.i64(zone.priority);
                    writer.count(zone.cells.len());
                    for cell in &zone.cells {
                        writer.count(cell.planes.len());
                        for plane in &cell.planes {
                            writer.i64(plane.a);
                            writer.i64(plane.b);
                            writer.i64(plane.c);
                            writer.i128(plane.offset);
                        }
                    }
                }
            }
            SpatialArtifactKind::PathProfile { path, points } => {
                writer.byte(4);
                writer.text(path.as_str());
                writer.count(points.len());
                for point in points {
                    writer.u64(point.distance_mm);
                    writer.position(point.position_mm);
                    writer.value(&point.value);
                }
            }
            SpatialArtifactKind::TransmitterLookup {
                model,
                transmitter_mm,
                distance_values,
                orientation_values,
                environment_coefficients,
            } => {
                writer.byte(5);
                writer.text(model.as_str());
                writer.position(*transmitter_mm);
                writer.count(distance_values.len());
                for (distance, value) in distance_values {
                    writer.u64(*distance);
                    writer.value(value);
                }
                writer.count(orientation_values.len());
                for (orientation, value) in orientation_values {
                    writer.position(*orientation);
                    writer.value(value);
                }
                writer.count(environment_coefficients.len());
                for coefficient in environment_coefficients {
                    writer.ratio(*coefficient);
                }
            }
        }
        writer.bytes
    }

    /// Decodes, revalidates, and proves canonical byte identity.
    ///
    /// # Errors
    ///
    /// Returns [`SpatialArtifactError`] for malformed, unsupported,
    /// noncanonical, oversized, or trailing input.
    pub fn decode(bytes: &[u8]) -> Result<Self, SpatialArtifactError> {
        let mut reader = SpatialReader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(SpatialArtifactError::MalformedCodec);
        }
        let version = reader.u16()?;
        if version != SPATIAL_CODEC_VERSION {
            return Err(SpatialArtifactError::VersionMismatch {
                expected: SPATIAL_CODEC_VERSION,
                actual: version,
            });
        }
        let frame = reader.id()?;
        let shape = decode_signal_shape(reader.blob()?).map_err(SpatialArtifactError::Trace)?;
        let kind = match reader.byte()? {
            0 => {
                let samples = reader.samples()?;
                let count = reader.count(HARD_SPATIAL_ITEMS)?;
                let mut simplices = Vec::with_capacity(count);
                for _ in 0..count {
                    let vertex_count = reader.count(4)?;
                    if !(2..=4).contains(&vertex_count) {
                        return Err(SpatialArtifactError::InvalidItems);
                    }
                    let mut vertices = Vec::with_capacity(vertex_count);
                    for _ in 0..vertex_count {
                        vertices.push(reader.u32()?);
                    }
                    simplices.push(SpatialSimplex { vertices });
                }
                SpatialArtifactKind::PointSet { samples, simplices }
            }
            1 => {
                let origin_mm = reader.position()?;
                let cell_size_mm = reader.u64_array()?;
                let dimensions = reader.u32_array()?;
                let count = reader.count(HARD_SPATIAL_ITEMS)?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(reader.value()?);
                }
                SpatialArtifactKind::RegularGrid {
                    origin_mm,
                    cell_size_mm,
                    dimensions,
                    values,
                }
            }
            2 => {
                let count = reader.count(HARD_SPATIAL_TILES)?;
                let mut tiles = Vec::with_capacity(count);
                for _ in 0..count {
                    tiles.push(SpatialTileReference {
                        minimum_mm: reader.position()?,
                        maximum_mm: reader.position()?,
                        content: reader.hash()?,
                    });
                }
                SpatialArtifactKind::TiledGrid { tiles }
            }
            3 => {
                let outside = reader.id()?;
                let count = reader.count(HARD_SPATIAL_ITEMS)?;
                let mut remaining_geometry = HARD_SPATIAL_ITEMS
                    .checked_sub(count)
                    .ok_or(SpatialArtifactError::ItemLimit)?;
                let mut zones = Vec::new();
                for _ in 0..count {
                    let id = reader.id()?;
                    let priority = reader.i64()?;
                    let cell_count = reader.count(remaining_geometry)?;
                    remaining_geometry = remaining_geometry
                        .checked_sub(cell_count)
                        .ok_or(SpatialArtifactError::ItemLimit)?;
                    let mut cells = Vec::new();
                    for _ in 0..cell_count {
                        let plane_count = reader.count(remaining_geometry)?;
                        remaining_geometry = remaining_geometry
                            .checked_sub(plane_count)
                            .ok_or(SpatialArtifactError::ItemLimit)?;
                        let mut planes = Vec::new();
                        for _ in 0..plane_count {
                            planes.push(SpatialPlane {
                                a: reader.i64()?,
                                b: reader.i64()?,
                                c: reader.i64()?,
                                offset: reader.i128()?,
                            });
                        }
                        cells.push(SpatialConvexCell { planes });
                    }
                    zones.push(SpatialZone {
                        id,
                        priority,
                        cells,
                    });
                }
                SpatialArtifactKind::ZoneMap { outside, zones }
            }
            4 => {
                let path = reader.id()?;
                let count = reader.count(HARD_SPATIAL_ITEMS)?;
                let mut points = Vec::with_capacity(count);
                for _ in 0..count {
                    points.push(SpatialPathPoint {
                        distance_mm: reader.u64()?,
                        position_mm: reader.position()?,
                        value: reader.value()?,
                    });
                }
                SpatialArtifactKind::PathProfile { path, points }
            }
            5 => {
                let model = reader.id()?;
                let transmitter_mm = reader.position()?;
                let count = reader.count(HARD_SPATIAL_ITEMS)?;
                let mut distance_values = Vec::with_capacity(count);
                for _ in 0..count {
                    distance_values.push((reader.u64()?, reader.value()?));
                }
                let count = reader.count(HARD_SPATIAL_ITEMS)?;
                let mut orientation_values = Vec::with_capacity(count);
                for _ in 0..count {
                    orientation_values.push((reader.position()?, reader.value()?));
                }
                let count = reader.count(HARD_SIGNAL_INPUTS_PER_NODE_LIMIT.into())?;
                let mut environment_coefficients = Vec::with_capacity(count);
                for _ in 0..count {
                    environment_coefficients.push(reader.ratio()?);
                }
                SpatialArtifactKind::TransmitterLookup {
                    model,
                    transmitter_mm,
                    distance_values,
                    orientation_values,
                    environment_coefficients,
                }
            }
            _ => return Err(SpatialArtifactError::MalformedCodec),
        };
        if !reader.remaining().is_empty() {
            return Err(SpatialArtifactError::TrailingBytes);
        }
        let artifact = Self::new(frame, shape, kind)?;
        if artifact.encode() != bytes {
            return Err(SpatialArtifactError::NonCanonicalCodec);
        }
        Ok(artifact)
    }
}

fn validate_kind(
    shape: &SignalShape,
    kind: &SpatialArtifactKind,
) -> Result<(), SpatialArtifactError> {
    let value_ok = |value: &SignalValue| value.value_type().as_ref() == Some(&shape.value_type);
    match kind {
        SpatialArtifactKind::PointSet { samples, simplices } => {
            if samples.is_empty()
                || samples.len() > HARD_SPATIAL_ITEMS
                || samples
                    .windows(2)
                    .any(|pair| pair[0].position_mm >= pair[1].position_mm)
                || samples.iter().any(|sample| !value_ok(&sample.value))
                || simplices.len() > HARD_SPATIAL_ITEMS
                || simplices.windows(2).any(|pair| pair[0] >= pair[1])
                || simplices.iter().any(|simplex| {
                    !(2..=4).contains(&simplex.vertices.len())
                        || simplex.vertices.windows(2).any(|pair| pair[0] >= pair[1])
                        || simplex.vertices.iter().any(|vertex| {
                            usize::try_from(*vertex).map_or(true, |index| index >= samples.len())
                        })
                        || simplex_is_degenerate(samples, simplex)
                })
            {
                return Err(SpatialArtifactError::InvalidItems);
            }
        }
        SpatialArtifactKind::RegularGrid {
            cell_size_mm,
            dimensions,
            values,
            ..
        } => {
            let expected = dimensions.iter().try_fold(1_u64, |total, dimension| {
                total.checked_mul(u64::from(*dimension))
            });
            if cell_size_mm.contains(&0)
                || dimensions.contains(&0)
                || expected != u64::try_from(values.len()).ok()
                || values.len() > HARD_SPATIAL_ITEMS
                || values.iter().any(|value| !value_ok(value))
            {
                return Err(SpatialArtifactError::InvalidGrid);
            }
        }
        SpatialArtifactKind::TiledGrid { tiles } => {
            if tiles.is_empty()
                || tiles.len() > HARD_SPATIAL_TILES
                || tiles.iter().any(|tile| {
                    tile.minimum_mm
                        .iter()
                        .zip(tile.maximum_mm)
                        .any(|(minimum, maximum)| *minimum >= maximum)
                })
                || tiles.windows(2).any(|pair| pair[0] >= pair[1])
                || tiles_have_overlap(tiles)
            {
                return Err(SpatialArtifactError::InvalidTiles);
            }
        }
        SpatialArtifactKind::ZoneMap { outside, zones } => {
            if !matches!(shape.value_type, SignalValueType::Enum(_))
                || zones.is_empty()
                || zones.len() > HARD_SPATIAL_ITEMS
                || zone_geometry_items(zones).is_none_or(|items| items > HARD_SPATIAL_ITEMS)
                || zones.iter().any(|zone| {
                    zone.id == *outside
                        || zone.cells.is_empty()
                        || zone.cells.iter().any(|cell| {
                            cell.planes.is_empty()
                                || cell
                                    .planes
                                    .iter()
                                    .any(|plane| plane.a == 0 && plane.b == 0 && plane.c == 0)
                        })
                })
                || zones.windows(2).any(|pair| {
                    pair[0].priority < pair[1].priority
                        || (pair[0].priority == pair[1].priority && pair[0].id >= pair[1].id)
                })
            {
                return Err(SpatialArtifactError::InvalidZones);
            }
        }
        SpatialArtifactKind::PathProfile { points, .. } => {
            if points.len() < 2
                || points.len() > HARD_SPATIAL_ITEMS
                || points.windows(2).any(|pair| {
                    pair[0].distance_mm >= pair[1].distance_mm
                        || pair[0].position_mm == pair[1].position_mm
                })
                || points.iter().any(|point| !value_ok(&point.value))
            {
                return Err(SpatialArtifactError::InvalidPath);
            }
        }
        SpatialArtifactKind::TransmitterLookup {
            distance_values,
            orientation_values,
            environment_coefficients,
            ..
        } => {
            if distance_values.is_empty()
                || distance_values.len() > HARD_SPATIAL_ITEMS
                || distance_values
                    .windows(2)
                    .any(|pair| pair[0].0 >= pair[1].0)
                || distance_values.iter().any(|(_, value)| !value_ok(value))
                || orientation_values.len() > HARD_SPATIAL_ITEMS
                || orientation_values
                    .windows(2)
                    .any(|pair| pair[0].0 >= pair[1].0)
                || orientation_values.iter().any(|(orientation, value)| {
                    orientation
                        .iter()
                        .any(|angle| !(-180_000..=180_000).contains(angle))
                        || !value_ok(value)
                })
                || environment_coefficients.len() > usize::from(HARD_SIGNAL_INPUTS_PER_NODE_LIMIT)
            {
                return Err(SpatialArtifactError::InvalidTransmitter);
            }
        }
    }
    Ok(())
}

fn tiles_overlap(left: SpatialTileReference, right: SpatialTileReference) -> bool {
    (0..3).all(|index| {
        left.minimum_mm[index] < right.maximum_mm[index]
            && right.minimum_mm[index] < left.maximum_mm[index]
    })
}

fn tiles_have_overlap(tiles: &[SpatialTileReference]) -> bool {
    let mut active = Vec::new();
    for tile in tiles {
        active.retain(|prior: &&SpatialTileReference| prior.maximum_mm[0] > tile.minimum_mm[0]);
        if active.iter().any(|prior| tiles_overlap(**prior, *tile)) {
            return true;
        }
        active.push(tile);
    }
    false
}

fn zone_geometry_items(zones: &[SpatialZone]) -> Option<usize> {
    zones.iter().try_fold(zones.len(), |total, zone| {
        zone.cells
            .iter()
            .try_fold(total.checked_add(zone.cells.len())?, |total, cell| {
                total.checked_add(cell.planes.len())
            })
    })
}

#[derive(Default)]
struct SpatialWriter {
    bytes: Vec<u8>,
}

impl SpatialWriter {
    fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn count(&mut self, value: usize) {
        self.u32(u32::try_from(value).unwrap_or(u32::MAX));
    }

    fn text(&mut self, value: &str) {
        self.count(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn blob(&mut self, value: &[u8]) {
        self.count(value.len());
        self.bytes.extend_from_slice(value);
    }

    fn position(&mut self, value: [i64; 3]) {
        for component in value {
            self.i64(component);
        }
    }

    fn u64_array(&mut self, value: [u64; 3]) {
        for component in value {
            self.u64(component);
        }
    }

    fn u32_array(&mut self, value: [u32; 3]) {
        for component in value {
            self.u32(component);
        }
    }

    fn ratio(&mut self, value: ExactRatio) {
        self.i64(value.numerator());
        self.u64(value.denominator());
    }

    fn value(&mut self, value: &SignalValue) {
        self.blob(&encode_signal_value(value).unwrap_or_default());
    }
}

struct SpatialReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> SpatialReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.cursor..]
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SpatialArtifactError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(SpatialArtifactError::MalformedCodec)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SpatialArtifactError::MalformedCodec)?;
        self.cursor = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, SpatialArtifactError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SpatialArtifactError> {
        let bytes = self
            .take(2)?
            .try_into()
            .map_err(|_| SpatialArtifactError::MalformedCodec)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, SpatialArtifactError> {
        let bytes = self
            .take(4)?
            .try_into()
            .map_err(|_| SpatialArtifactError::MalformedCodec)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, SpatialArtifactError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| SpatialArtifactError::MalformedCodec)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, SpatialArtifactError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| SpatialArtifactError::MalformedCodec)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn i128(&mut self) -> Result<i128, SpatialArtifactError> {
        let bytes = self
            .take(16)?
            .try_into()
            .map_err(|_| SpatialArtifactError::MalformedCodec)?;
        Ok(i128::from_be_bytes(bytes))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, SpatialArtifactError> {
        let count = usize::try_from(self.u32()?).map_err(|_| SpatialArtifactError::ItemLimit)?;
        if count > maximum {
            return Err(SpatialArtifactError::ItemLimit);
        }
        Ok(count)
    }

    fn blob(&mut self) -> Result<&'a [u8], SpatialArtifactError> {
        let length = self.count(HARD_TRACE_VALUE_BYTES)?;
        self.take(length)
    }

    fn text(&mut self) -> Result<&'a str, SpatialArtifactError> {
        std::str::from_utf8(self.blob()?).map_err(|_| SpatialArtifactError::MalformedCodec)
    }

    fn id(&mut self) -> Result<SignalId, SpatialArtifactError> {
        SignalId::parse(self.text()?).map_err(SpatialArtifactError::Program)
    }

    fn hash(&mut self) -> Result<ContentHash, SpatialArtifactError> {
        let bytes = self
            .take(32)?
            .try_into()
            .map_err(|_| SpatialArtifactError::MalformedCodec)?;
        Ok(ContentHash { bytes })
    }

    fn position(&mut self) -> Result<[i64; 3], SpatialArtifactError> {
        Ok([self.i64()?, self.i64()?, self.i64()?])
    }

    fn u64_array(&mut self) -> Result<[u64; 3], SpatialArtifactError> {
        Ok([self.u64()?, self.u64()?, self.u64()?])
    }

    fn u32_array(&mut self) -> Result<[u32; 3], SpatialArtifactError> {
        Ok([self.u32()?, self.u32()?, self.u32()?])
    }

    fn ratio(&mut self) -> Result<ExactRatio, SpatialArtifactError> {
        ExactRatio::new(self.i64()?, self.u64()?).map_err(SpatialArtifactError::Program)
    }

    fn value(&mut self) -> Result<SignalValue, SpatialArtifactError> {
        decode_signal_value(self.blob()?).map_err(SpatialArtifactError::Trace)
    }

    fn samples(&mut self) -> Result<Vec<SpatialSample>, SpatialArtifactError> {
        let count = self.count(HARD_SPATIAL_ITEMS)?;
        let mut samples = Vec::with_capacity(count);
        for _ in 0..count {
            samples.push(SpatialSample {
                position_mm: self.position()?,
                value: self.value()?,
            });
        }
        Ok(samples)
    }
}

mod sampling;

pub(in crate::model::fault_signal) use sampling::evaluate_normalized_spatial_source;
use sampling::simplex_is_degenerate;
#[cfg(test)]
use sampling::{RegularGrid, sample_point_set, sample_regular_grid};

/// Normalized spatial artifact construction or codec failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpatialArtifactError {
    /// Codec version differs from the implemented version.
    VersionMismatch {
        /// Implemented version.
        expected: u16,
        /// Encoded version.
        actual: u16,
    },
    /// A count exceeded its hard ceiling.
    ItemLimit,
    /// Point samples were empty, malformed, unordered, or shape-incompatible.
    InvalidItems,
    /// Grid dimensions, cells, value count, or values were invalid.
    InvalidGrid,
    /// Tile bounds, ordering, overlap, or count were invalid.
    InvalidTiles,
    /// Zone geometry, order, variants, or output shape were invalid.
    InvalidZones,
    /// Path vertices, distances, values, or ordering were invalid.
    InvalidPath,
    /// Transmitter lookup or environment coefficients were invalid.
    InvalidTransmitter,
    /// Binary framing is truncated or has an unknown tag.
    MalformedCodec,
    /// Binary input contains trailing bytes.
    TrailingBytes,
    /// Decoded content does not reproduce the original bytes.
    NonCanonicalCodec,
    /// Nested signal contract failed.
    Program(SignalProgramError),
    /// Nested value or shape codec failed.
    Trace(TraceError),
}

impl fmt::Display for SpatialArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid normalized spatial artifact: {self:?}")
    }
}

impl Error for SpatialArtifactError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> SignalId {
        match SignalId::parse(value) {
            Ok(value) => value,
            Err(error) => panic!("test ID must be valid: {error}"),
        }
    }

    #[test]
    fn regular_grid_codec_is_canonical() {
        let shape = match SignalShape::new(SignalValueType::I64, SignalUnit::Millidecibels, 0) {
            Ok(value) => value,
            Err(error) => panic!("test shape must be valid: {error}"),
        };
        let artifact = match NormalizedSpatialArtifact::new(
            id("local-frame"),
            shape,
            SpatialArtifactKind::RegularGrid {
                origin_mm: [0; 3],
                cell_size_mm: [10; 3],
                dimensions: [2, 1, 1],
                values: vec![SignalValue::I64(-10), SignalValue::I64(-20)],
            },
        ) {
            Ok(value) => value,
            Err(error) => panic!("test artifact must be valid: {error}"),
        };
        assert_eq!(
            NormalizedSpatialArtifact::decode(&artifact.encode()),
            Ok(artifact)
        );
    }

    #[test]
    fn point_set_linear_interpolation_uses_declared_tetrahedron() {
        let samples = vec![
            SpatialSample {
                position_mm: [0, 0, 0],
                value: SignalValue::I64(0),
            },
            SpatialSample {
                position_mm: [0, 0, 10],
                value: SignalValue::I64(30),
            },
            SpatialSample {
                position_mm: [0, 10, 0],
                value: SignalValue::I64(20),
            },
            SpatialSample {
                position_mm: [10, 0, 0],
                value: SignalValue::I64(10),
            },
        ];
        let simplices = vec![SpatialSimplex {
            vertices: vec![0, 1, 2, 3],
        }];
        let sampled = sample_point_set(
            &samples,
            &simplices,
            [2, 2, 2],
            SignalInterpolation::Linear {
                rounding: SignalRounding::NearestTiesToEven,
                overflow: SignalOverflow::Error,
            },
            &SignalBoundaryBehavior::Error,
        );
        assert!(matches!(
            sampled,
            Ok(EvaluatedSignal::Value(SignalValue::I64(12)))
        ));
    }

    #[test]
    fn regular_grid_uses_outside_policy_past_its_final_sample() {
        let sampled = sample_regular_grid(
            RegularGrid {
                origin: [0; 3],
                cell: [10; 3],
                dimensions: [2, 1, 1],
                values: &[SignalValue::I64(1), SignalValue::I64(2)],
            },
            [15, 0, 0],
            SignalInterpolation::Nearest,
            &SignalBoundaryBehavior::Constant(SignalValue::I64(99)),
        );
        assert!(matches!(
            sampled,
            Ok(EvaluatedSignal::Value(SignalValue::I64(99)))
        ));
    }

    #[test]
    fn tiled_grid_rejects_nonadjacent_overlaps() {
        let tile = |minimum_mm, maximum_mm, name: &[u8]| SpatialTileReference {
            minimum_mm,
            maximum_mm,
            content: ContentHash::from_bytes(name),
        };
        let result = NormalizedSpatialArtifact::new(
            id("frame"),
            match SignalShape::new(SignalValueType::I64, SignalUnit::Dimensionless, 0) {
                Ok(value) => value,
                Err(error) => panic!("test shape must be valid: {error}"),
            },
            SpatialArtifactKind::TiledGrid {
                tiles: vec![
                    tile([0, 0, 0], [100, 10, 10], b"large"),
                    tile([10, 20, 0], [20, 30, 10], b"middle"),
                    tile([30, 0, 0], [40, 10, 10], b"overlap"),
                ],
            },
        );
        assert!(matches!(result, Err(SpatialArtifactError::InvalidTiles)));
    }

    #[test]
    fn zone_order_accepts_the_minimum_priority_without_overflow() {
        let cell = || SpatialConvexCell {
            planes: vec![SpatialPlane {
                a: 1,
                b: 0,
                c: 0,
                offset: 100,
            }],
        };
        let result = NormalizedSpatialArtifact::new(
            id("frame"),
            match SignalShape::new(
                SignalValueType::Enum(id("zone-schema")),
                SignalUnit::Dimensionless,
                0,
            ) {
                Ok(value) => value,
                Err(error) => panic!("test shape must be valid: {error}"),
            },
            SpatialArtifactKind::ZoneMap {
                outside: id("outside"),
                zones: vec![
                    SpatialZone {
                        id: id("high"),
                        priority: 0,
                        cells: vec![cell()],
                    },
                    SpatialZone {
                        id: id("low"),
                        priority: i64::MIN,
                        cells: vec![cell()],
                    },
                ],
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn zone_decoder_rejects_aggregate_geometry_before_allocating() {
        let shape = match SignalShape::new(
            SignalValueType::Enum(id("zone-schema")),
            SignalUnit::Dimensionless,
            0,
        ) {
            Ok(value) => value,
            Err(error) => panic!("test shape must be valid: {error}"),
        };
        let mut writer = SpatialWriter::default();
        writer.bytes.extend_from_slice(MAGIC);
        writer.u16(SPATIAL_CODEC_VERSION);
        writer.text("frame");
        writer.blob(&encode_signal_shape(&shape).unwrap_or_default());
        writer.byte(3);
        writer.text("outside");
        writer.count(1);
        writer.text("zone");
        writer.i64(0);
        writer.count(HARD_SPATIAL_ITEMS);
        assert!(matches!(
            NormalizedSpatialArtifact::decode(&writer.bytes),
            Err(SpatialArtifactError::ItemLimit)
        ));
    }
}
