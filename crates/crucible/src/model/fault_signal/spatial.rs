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

/// Evaluates one normalized spatial source from the production DAG store.
pub(super) fn evaluate_normalized_spatial_source(
    store: &dyn DagStore,
    node: &SignalNode,
    source: &SignalSourceSpecification,
    coordinate: &SignalCoordinate,
    inputs: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let transmitter_position = matches!(source, SignalSourceSpecification::TransmitterField { .. });
    let [x, y, z] = if transmitter_position {
        position_vector(
            inputs
                .first()
                .ok_or(SignalEvaluationError::TypeMismatch)?
                .value()?,
        )?
    } else {
        spatial_position(coordinate)?
    };
    let content = spatial_content(source)?;
    let bytes = store.get(&content).map_err(SignalEvaluationError::Store)?;
    if ContentHash::from_bytes(&bytes) != content {
        return Err(SignalEvaluationError::ArtifactContentMismatch(content));
    }
    let artifact = NormalizedSpatialArtifact::decode(&bytes)
        .map_err(SignalEvaluationError::SpatialArtifact)?;
    if artifact.content() != content || artifact.shape() != &node.output {
        return Err(SignalEvaluationError::SpatialArtifactMismatch(
            node.id.clone(),
        ));
    }
    if !transmitter_position {
        let frame = match coordinate {
            SignalCoordinate::Spatial { frame, .. } => frame,
            _ => return Err(SignalEvaluationError::SpatialCoordinateRequired),
        };
        if artifact.frame() != frame {
            return Err(SignalEvaluationError::SpatialFrameMismatch);
        }
    }
    match (source, artifact.kind()) {
        (
            SignalSourceSpecification::PointSet {
                interpolation,
                outside,
                ..
            },
            SpatialArtifactKind::PointSet { samples, simplices },
        ) => sample_point_set(samples, simplices, [x, y, z], *interpolation, outside),
        (
            SignalSourceSpecification::RegularGrid {
                origin_mm,
                cell_size_mm,
                dimensions,
                interpolation,
                outside,
                ..
            },
            SpatialArtifactKind::RegularGrid {
                origin_mm: stored_origin,
                cell_size_mm: stored_cells,
                dimensions: stored_dimensions,
                values,
            },
        ) if origin_mm == stored_origin
            && cell_size_mm == stored_cells
            && dimensions == stored_dimensions =>
        {
            sample_regular_grid(
                *origin_mm,
                *cell_size_mm,
                *dimensions,
                values,
                [x, y, z],
                *interpolation,
                outside,
            )
        }
        (
            SignalSourceSpecification::TiledGrid {
                tile_size_mm,
                interpolation,
                outside,
                ..
            },
            SpatialArtifactKind::TiledGrid { tiles },
        ) => sample_tiled_grid(
            store,
            artifact.frame(),
            tiles,
            *tile_size_mm,
            [x, y, z],
            *interpolation,
            outside,
        ),
        (
            SignalSourceSpecification::ZoneMap {
                boundary, overlap, ..
            },
            SpatialArtifactKind::ZoneMap { outside, zones },
        ) => sample_zone_map(node, outside, zones, [x, y, z], boundary, overlap),
        (
            SignalSourceSpecification::PathProfile {
                path,
                interpolation,
                before,
                after,
                ..
            },
            SpatialArtifactKind::PathProfile {
                path: stored_path,
                points,
            },
        ) if path == stored_path => {
            sample_path_profile(points, [x, y, z], *interpolation, before, after)
        }
        (
            SignalSourceSpecification::TransmitterField {
                model,
                coordinate_frame,
                orientation_signal,
                environment_signals,
                ..
            },
            SpatialArtifactKind::TransmitterLookup {
                model: stored_model,
                transmitter_mm,
                distance_values,
                orientation_values,
                environment_coefficients,
            },
        ) if model == stored_model
            && coordinate_frame == artifact.frame()
            && environment_signals.len() == environment_coefficients.len() =>
        {
            sample_transmitter(
                *transmitter_mm,
                distance_values,
                orientation_values,
                environment_coefficients,
                [x, y, z],
                orientation_signal
                    .as_ref()
                    .map(|_| inputs.get(1).ok_or(SignalEvaluationError::TypeMismatch))
                    .transpose()?,
                inputs
                    .get(1 + usize::from(orientation_signal.is_some())..)
                    .ok_or(SignalEvaluationError::TypeMismatch)?,
            )
        }
        _ => Err(SignalEvaluationError::SpatialArtifactMismatch(
            node.id.clone(),
        )),
    }
}

fn spatial_content(
    source: &SignalSourceSpecification,
) -> Result<ContentHash, SignalEvaluationError> {
    match source {
        SignalSourceSpecification::PointSet { artifact, .. }
        | SignalSourceSpecification::RegularGrid { artifact, .. }
        | SignalSourceSpecification::ZoneMap { artifact, .. }
        | SignalSourceSpecification::PathProfile { artifact, .. } => Ok(*artifact),
        SignalSourceSpecification::TiledGrid { manifest, .. } => Ok(*manifest),
        SignalSourceSpecification::TransmitterField { lookup, .. } => Ok(*lookup),
        _ => Err(SignalEvaluationError::ArtifactSourceRequired(
            SignalId::parse("spatial-source").map_err(SignalEvaluationError::Program)?,
        )),
    }
}

fn spatial_position(coordinate: &SignalCoordinate) -> Result<[i64; 3], SignalEvaluationError> {
    match coordinate {
        SignalCoordinate::Spatial {
            x_mm, y_mm, z_mm, ..
        } => Ok([*x_mm, *y_mm, *z_mm]),
        _ => Err(SignalEvaluationError::SpatialCoordinateRequired),
    }
}

fn sample_point_set(
    samples: &[SpatialSample],
    simplices: &[SpatialSimplex],
    position: [i64; 3],
    interpolation: SignalInterpolation,
    outside: &SignalBoundaryBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if let Ok(index) = samples.binary_search_by_key(&position, |sample| sample.position_mm) {
        return Ok(EvaluatedSignal::Value(samples[index].value.clone()));
    }
    match interpolation {
        SignalInterpolation::Exact => evaluate_boundary(outside, None, None),
        SignalInterpolation::HoldPrevious => samples
            .iter()
            .rfind(|sample| sample.position_mm <= position)
            .map(|sample| EvaluatedSignal::Value(sample.value.clone()))
            .map_or_else(
                || evaluate_boundary(outside, samples.first().map(|sample| &sample.value), None),
                Ok,
            ),
        SignalInterpolation::Nearest => {
            let sample = samples
                .iter()
                .min_by_key(|sample| {
                    (
                        squared_distance(sample.position_mm, position).unwrap_or(u128::MAX),
                        sample.position_mm,
                    )
                })
                .ok_or(SignalEvaluationError::SpatialOutsideExtent)?;
            Ok(EvaluatedSignal::Value(sample.value.clone()))
        }
        SignalInterpolation::Linear { rounding, overflow } => {
            for simplex in simplices {
                if let Some((weights, denominator)) = simplex_weights(samples, simplex, position)? {
                    let values = simplex
                        .vertices
                        .iter()
                        .map(|index| {
                            samples
                                .get(
                                    usize::try_from(*index)
                                        .map_err(|_| SignalEvaluationError::SpatialArtifactIndex)?,
                                )
                                .map(|sample| &sample.value)
                                .ok_or(SignalEvaluationError::SpatialArtifactIndex)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    return Ok(EvaluatedSignal::Value(weighted_value(
                        &values,
                        &weights,
                        denominator,
                        rounding,
                        overflow,
                    )?));
                }
            }
            evaluate_boundary(outside, None, None)
        }
    }
}

fn simplex_is_degenerate(samples: &[SpatialSample], simplex: &SpatialSimplex) -> bool {
    let vertices = simplex
        .vertices
        .iter()
        .filter_map(|index| usize::try_from(*index).ok())
        .filter_map(|index| samples.get(index))
        .map(|sample| sample.position_mm)
        .collect::<Vec<_>>();
    match vertices.as_slice() {
        [left, right] => left == right,
        [origin, left, right] => cross(vector(*origin, *left), vector(*origin, *right))
            .is_none_or(|value| value == [0; 3]),
        [origin, a, b, c] => determinant(
            vector(*origin, *a),
            vector(*origin, *b),
            vector(*origin, *c),
        )
        .is_none_or(|value| value == 0),
        _ => true,
    }
}

fn simplex_weights(
    samples: &[SpatialSample],
    simplex: &SpatialSimplex,
    point: [i64; 3],
) -> Result<Option<(Vec<u128>, u128)>, SignalEvaluationError> {
    let vertices = simplex
        .vertices
        .iter()
        .map(|index| {
            samples
                .get(
                    usize::try_from(*index)
                        .map_err(|_| SignalEvaluationError::SpatialArtifactIndex)?,
                )
                .map(|sample| sample.position_mm)
                .ok_or(SignalEvaluationError::SpatialArtifactIndex)
        })
        .collect::<Result<Vec<_>, _>>()?;
    match vertices.as_slice() {
        [left, right] => Ok(segment_fraction(*left, *right, point)?.map(
            |(numerator, denominator)| {
                (
                    vec![u128::from(denominator - numerator), u128::from(numerator)],
                    u128::from(denominator),
                )
            },
        )),
        [origin, left, right] => triangle_weights(*origin, *left, *right, point),
        [origin, a, b, c] => tetrahedron_weights(*origin, *a, *b, *c, point),
        _ => Ok(None),
    }
}

fn segment_fraction(
    left: [i64; 3],
    right: [i64; 3],
    point: [i64; 3],
) -> Result<Option<(u64, u64)>, SignalEvaluationError> {
    let direction = [
        i128::from(right[0]) - i128::from(left[0]),
        i128::from(right[1]) - i128::from(left[1]),
        i128::from(right[2]) - i128::from(left[2]),
    ];
    let relative = [
        i128::from(point[0]) - i128::from(left[0]),
        i128::from(point[1]) - i128::from(left[1]),
        i128::from(point[2]) - i128::from(left[2]),
    ];
    let denominator = dot(direction, direction)?;
    let numerator = dot(relative, direction)?;
    if denominator <= 0 || numerator < 0 || numerator > denominator {
        return Ok(None);
    }
    for index in 0..3 {
        if relative[index]
            .checked_mul(denominator)
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?
            != direction[index]
                .checked_mul(numerator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?
        {
            return Ok(None);
        }
    }
    Ok(Some((
        u64::try_from(numerator).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        u64::try_from(denominator).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
    )))
}

fn dot(left: [i128; 3], right: [i128; 3]) -> Result<i128, SignalEvaluationError> {
    left.into_iter()
        .zip(right)
        .try_fold(0_i128, |total, (left, right)| {
            left.checked_mul(right)
                .and_then(|value| total.checked_add(value))
                .ok_or(SignalEvaluationError::ArithmeticOverflow)
        })
}

fn vector(origin: [i64; 3], point: [i64; 3]) -> [i128; 3] {
    [
        i128::from(point[0]) - i128::from(origin[0]),
        i128::from(point[1]) - i128::from(origin[1]),
        i128::from(point[2]) - i128::from(origin[2]),
    ]
}

fn cross(left: [i128; 3], right: [i128; 3]) -> Option<[i128; 3]> {
    Some([
        left[1]
            .checked_mul(right[2])?
            .checked_sub(left[2].checked_mul(right[1])?)?,
        left[2]
            .checked_mul(right[0])?
            .checked_sub(left[0].checked_mul(right[2])?)?,
        left[0]
            .checked_mul(right[1])?
            .checked_sub(left[1].checked_mul(right[0])?)?,
    ])
}

fn determinant(a: [i128; 3], b: [i128; 3], c: [i128; 3]) -> Option<i128> {
    dot(a, cross(b, c)?).ok()
}

fn triangle_weights(
    origin: [i64; 3],
    left: [i64; 3],
    right: [i64; 3],
    point: [i64; 3],
) -> Result<Option<(Vec<u128>, u128)>, SignalEvaluationError> {
    let a = vector(origin, left);
    let b = vector(origin, right);
    let p = vector(origin, point);
    let aa = dot(a, a)?;
    let ab = dot(a, b)?;
    let bb = dot(b, b)?;
    let pa = dot(p, a)?;
    let pb = dot(p, b)?;
    let denominator = aa
        .checked_mul(bb)
        .and_then(|value| value.checked_sub(ab.checked_mul(ab)?))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    if denominator <= 0 {
        return Ok(None);
    }
    let left_weight = bb
        .checked_mul(pa)
        .and_then(|value| value.checked_sub(ab.checked_mul(pb)?))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let right_weight = aa
        .checked_mul(pb)
        .and_then(|value| value.checked_sub(ab.checked_mul(pa)?))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let origin_weight = denominator
        .checked_sub(left_weight)
        .and_then(|value| value.checked_sub(right_weight))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    if [origin_weight, left_weight, right_weight]
        .iter()
        .any(|weight| *weight < 0)
    {
        return Ok(None);
    }
    for axis in 0..3 {
        let reconstructed = i128::from(origin[axis])
            .checked_mul(denominator)
            .and_then(|value| value.checked_add(a[axis].checked_mul(left_weight)?))
            .and_then(|value| value.checked_add(b[axis].checked_mul(right_weight)?))
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        if reconstructed
            != i128::from(point[axis])
                .checked_mul(denominator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?
        {
            return Ok(None);
        }
    }
    Ok(Some((
        vec![
            origin_weight.unsigned_abs(),
            left_weight.unsigned_abs(),
            right_weight.unsigned_abs(),
        ],
        denominator.unsigned_abs(),
    )))
}

fn tetrahedron_weights(
    origin: [i64; 3],
    a_point: [i64; 3],
    b_point: [i64; 3],
    c_point: [i64; 3],
    point: [i64; 3],
) -> Result<Option<(Vec<u128>, u128)>, SignalEvaluationError> {
    let a = vector(origin, a_point);
    let b = vector(origin, b_point);
    let c = vector(origin, c_point);
    let p = vector(origin, point);
    let denominator = determinant(a, b, c).ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    if denominator == 0 {
        return Ok(None);
    }
    let sign = denominator.signum();
    let wa = determinant(p, b, c)
        .and_then(|value| value.checked_mul(sign))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let wb = determinant(a, p, c)
        .and_then(|value| value.checked_mul(sign))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let wc = determinant(a, b, p)
        .and_then(|value| value.checked_mul(sign))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let denominator = denominator.unsigned_abs();
    let denominator_i128 =
        i128::try_from(denominator).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    let origin_weight = denominator_i128
        .checked_sub(wa)
        .and_then(|value| value.checked_sub(wb))
        .and_then(|value| value.checked_sub(wc))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    if [origin_weight, wa, wb, wc].iter().any(|weight| *weight < 0) {
        return Ok(None);
    }
    Ok(Some((
        vec![
            origin_weight.unsigned_abs(),
            wa.unsigned_abs(),
            wb.unsigned_abs(),
            wc.unsigned_abs(),
        ],
        denominator,
    )))
}

fn weighted_value(
    values: &[&SignalValue],
    weights: &[u128],
    weight_denominator: u128,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match values.first().copied() {
        Some(SignalValue::Vector2(first)) | Some(SignalValue::Vector3(first)) => {
            let mut components = Vec::with_capacity(first.len());
            for index in 0..first.len() {
                let component_values = values
                    .iter()
                    .map(|value| match value {
                        SignalValue::Vector2(values) | SignalValue::Vector3(values) => {
                            values.get(index).ok_or(SignalEvaluationError::TypeMismatch)
                        }
                        _ => Err(SignalEvaluationError::TypeMismatch),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                components.push(weighted_value(
                    &component_values,
                    weights,
                    weight_denominator,
                    rounding,
                    overflow,
                )?);
            }
            Ok(if matches!(values[0], SignalValue::Vector2(_)) {
                SignalValue::Vector2(components)
            } else {
                SignalValue::Vector3(components)
            })
        }
        Some(template) => {
            let mut numerator = 0_i128;
            let mut denominator = 1_u128;
            for (value, weight) in values.iter().zip(weights) {
                let (value_numerator, value_denominator) = numeric_fraction(value)?;
                let term_numerator = value_numerator
                    .checked_mul(
                        i128::try_from(*weight)
                            .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
                    )
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
                let term_denominator = value_denominator
                    .checked_mul(weight_denominator)
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
                let common = gcd_u128(denominator, term_denominator);
                let left_scale = term_denominator / common;
                let right_scale = denominator / common;
                numerator = numerator
                    .checked_mul(
                        i128::try_from(left_scale)
                            .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
                    )
                    .and_then(|value| {
                        term_numerator
                            .checked_mul(i128::try_from(right_scale).ok()?)
                            .and_then(|term| value.checked_add(term))
                    })
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
                denominator = right_scale
                    .checked_mul(term_denominator)
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            }
            value_from_fraction(template, numerator, denominator, rounding, overflow)
        }
        None => Err(SignalEvaluationError::TypeMismatch),
    }
}

fn gcd_u128(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

// crucible-lint: allow rust-allow -- regular-grid sampling needs the full geometry, value field, position, and interpolation contract.
#[allow(clippy::too_many_arguments)]
fn sample_regular_grid(
    origin: [i64; 3],
    cell: [u64; 3],
    dimensions: [u32; 3],
    values: &[SignalValue],
    position: [i64; 3],
    interpolation: SignalInterpolation,
    outside: &SignalBoundaryBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let mut lower = [0_u32; 3];
    let mut remainder = [0_u64; 3];
    for axis in 0..3 {
        let offset = i128::from(position[axis]) - i128::from(origin[axis]);
        if offset < 0 {
            return evaluate_boundary(outside, values.first(), None);
        }
        let cell_i128 = i128::from(cell[axis]);
        let final_extent = cell_i128
            .checked_mul(i128::from(dimensions[axis] - 1))
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        if offset > final_extent {
            return evaluate_boundary(outside, values.last(), None);
        }
        let index = offset / cell_i128;
        lower[axis] =
            u32::try_from(index).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
        remainder[axis] = u64::try_from(offset % cell_i128)
            .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    }
    match interpolation {
        SignalInterpolation::Exact if remainder != [0; 3] => evaluate_boundary(outside, None, None),
        SignalInterpolation::Exact | SignalInterpolation::HoldPrevious => Ok(
            EvaluatedSignal::Value(grid_value(dimensions, values, lower)?.clone()),
        ),
        SignalInterpolation::Nearest => {
            let mut nearest = lower;
            for axis in 0..3 {
                if remainder[axis] > cell[axis] / 2 && nearest[axis] + 1 < dimensions[axis] {
                    nearest[axis] += 1;
                }
            }
            Ok(EvaluatedSignal::Value(
                grid_value(dimensions, values, nearest)?.clone(),
            ))
        }
        SignalInterpolation::Linear { rounding, overflow } => {
            let mut current = values_for_cube(dimensions, values, lower)?;
            for axis in 0..3 {
                let mut next = Vec::with_capacity(current.len() / 2);
                for pair in current.chunks_exact(2) {
                    next.push(interpolate_value(
                        &pair[0],
                        &pair[1],
                        remainder[axis],
                        cell[axis],
                        rounding,
                        overflow,
                    )?);
                }
                current = next;
            }
            Ok(EvaluatedSignal::Value(
                current
                    .into_iter()
                    .next()
                    .ok_or(SignalEvaluationError::SpatialOutsideExtent)?,
            ))
        }
    }
}

fn grid_value(
    dimensions: [u32; 3],
    values: &[SignalValue],
    index: [u32; 3],
) -> Result<&SignalValue, SignalEvaluationError> {
    let flat = u64::from(index[2])
        .checked_mul(u64::from(dimensions[1]))
        .and_then(|value| value.checked_add(u64::from(index[1])))
        .and_then(|value| value.checked_mul(u64::from(dimensions[0])))
        .and_then(|value| value.checked_add(u64::from(index[0])))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    values
        .get(usize::try_from(flat).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?)
        .ok_or(SignalEvaluationError::SpatialArtifactIndex)
}

fn values_for_cube(
    dimensions: [u32; 3],
    values: &[SignalValue],
    lower: [u32; 3],
) -> Result<Vec<SignalValue>, SignalEvaluationError> {
    let mut cube = Vec::with_capacity(8);
    for z in 0..=1 {
        for y in 0..=1 {
            for x in 0..=1 {
                let index = [
                    (lower[0] + x).min(dimensions[0] - 1),
                    (lower[1] + y).min(dimensions[1] - 1),
                    (lower[2] + z).min(dimensions[2] - 1),
                ];
                cube.push(grid_value(dimensions, values, index)?.clone());
            }
        }
    }
    // Reorder so each successive reduction interpolates X, then Y, then Z.
    Ok(cube)
}

fn sample_tiled_grid(
    store: &dyn DagStore,
    frame: &SignalId,
    tiles: &[SpatialTileReference],
    tile_size_mm: [u64; 3],
    position: [i64; 3],
    interpolation: SignalInterpolation,
    outside: &SignalBoundaryBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let tile = tiles.iter().find(|tile| {
        (0..3).all(|axis| {
            position[axis] >= tile.minimum_mm[axis] && position[axis] < tile.maximum_mm[axis]
        })
    });
    let Some(tile) = tile else {
        return evaluate_boundary(outside, None, None);
    };
    let bytes = store
        .get(&tile.content)
        .map_err(SignalEvaluationError::Store)?;
    if ContentHash::from_bytes(&bytes) != tile.content {
        return Err(SignalEvaluationError::ArtifactContentMismatch(tile.content));
    }
    let artifact = NormalizedSpatialArtifact::decode(&bytes)
        .map_err(SignalEvaluationError::SpatialArtifact)?;
    let SpatialArtifactKind::RegularGrid {
        origin_mm,
        cell_size_mm,
        dimensions,
        values,
    } = artifact.kind()
    else {
        return Err(SignalEvaluationError::SpatialTileKind);
    };
    for axis in 0..3 {
        let declared_extent = i128::from(tile.maximum_mm[axis])
            .checked_sub(i128::from(tile.minimum_mm[axis]))
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        let grid_extent = u128::from(dimensions[axis] - 1)
            .checked_mul(u128::from(cell_size_mm[axis]))
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        if declared_extent != i128::from(tile_size_mm[axis])
            || u128::try_from(declared_extent).ok() != Some(grid_extent)
        {
            return Err(SignalEvaluationError::SpatialTileBounds);
        }
    }
    if *origin_mm != tile.minimum_mm || artifact.frame() != frame {
        return Err(SignalEvaluationError::SpatialTileBounds);
    }
    sample_regular_grid(
        *origin_mm,
        *cell_size_mm,
        *dimensions,
        values,
        position,
        interpolation,
        outside,
    )
}

fn sample_zone_map(
    node: &SignalNode,
    outside: &SignalId,
    zones: &[SpatialZone],
    position: [i64; 3],
    boundary: &SignalId,
    overlap: &SignalId,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let inclusive = match boundary.as_str() {
        "inclusive" => true,
        "exclusive" => false,
        _ => {
            return Err(SignalEvaluationError::UnknownSpatialBoundary(
                boundary.clone(),
            ));
        }
    };
    if overlap.as_str() != "priority-then-id" {
        return Err(SignalEvaluationError::UnknownZoneOverlap(overlap.clone()));
    }
    let selected = zones
        .iter()
        .find(|zone| {
            zone.cells
                .iter()
                .any(|cell| cell_contains(cell, position, inclusive).unwrap_or(false))
        })
        .map_or(outside, |zone| &zone.id);
    let SignalValueType::Enum(schema) = &node.output.value_type else {
        return Err(SignalEvaluationError::TypeMismatch);
    };
    Ok(EvaluatedSignal::Value(SignalValue::Enum {
        schema: schema.clone(),
        variant: selected.clone(),
    }))
}

fn cell_contains(
    cell: &SpatialConvexCell,
    position: [i64; 3],
    inclusive: bool,
) -> Result<bool, SignalEvaluationError> {
    for plane in &cell.planes {
        let value = i128::from(plane.a)
            .checked_mul(i128::from(position[0]))
            .and_then(|value| {
                i128::from(plane.b)
                    .checked_mul(i128::from(position[1]))
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| {
                i128::from(plane.c)
                    .checked_mul(i128::from(position[2]))
                    .and_then(|term| value.checked_add(term))
            })
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        if if inclusive {
            value > plane.offset
        } else {
            value >= plane.offset
        } {
            return Ok(false);
        }
    }
    Ok(true)
}

fn sample_path_profile(
    points: &[SpatialPathPoint],
    position: [i64; 3],
    interpolation: SignalInterpolation,
    before: &SignalBoundaryBehavior,
    after: &SignalBoundaryBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let first_direction = vector(points[0].position_mm, points[1].position_mm);
    let first_relative = vector(points[0].position_mm, position);
    if dot(first_relative, first_direction)? < 0 {
        return evaluate_boundary(before, Some(&points[0].value), None);
    }
    let last_index = points.len() - 1;
    let last_direction = vector(
        points[last_index - 1].position_mm,
        points[last_index].position_mm,
    );
    let last_relative = vector(points[last_index - 1].position_mm, position);
    if dot(last_relative, last_direction)? > dot(last_direction, last_direction)? {
        return evaluate_boundary(after, Some(&points[last_index].value), None);
    }
    let mut best: Option<(u128, usize, u64, u64)> = None;
    for (index, pair) in points.windows(2).enumerate() {
        let left = pair[0].position_mm;
        let right = pair[1].position_mm;
        let direction = [
            i128::from(right[0]) - i128::from(left[0]),
            i128::from(right[1]) - i128::from(left[1]),
            i128::from(right[2]) - i128::from(left[2]),
        ];
        let relative = [
            i128::from(position[0]) - i128::from(left[0]),
            i128::from(position[1]) - i128::from(left[1]),
            i128::from(position[2]) - i128::from(left[2]),
        ];
        let denominator_i128 = dot(direction, direction)?;
        let projected = dot(relative, direction)?.clamp(0, denominator_i128);
        let denominator = u64::try_from(denominator_i128)
            .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
        let numerator =
            u64::try_from(projected).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
        let closest = [
            rational_coordinate(left[0], direction[0], numerator, denominator)?,
            rational_coordinate(left[1], direction[1], numerator, denominator)?,
            rational_coordinate(left[2], direction[2], numerator, denominator)?,
        ];
        let distance = squared_distance(closest, position)?;
        let candidate = (distance, index, numerator, denominator);
        if best.is_none_or(|best| candidate < best) {
            best = Some(candidate);
        }
    }
    let (_, index, numerator, denominator) =
        best.ok_or(SignalEvaluationError::SpatialOutsideExtent)?;
    let left = &points[index];
    let right = &points[index + 1];
    match interpolation {
        SignalInterpolation::Exact => {
            if numerator == 0 {
                Ok(EvaluatedSignal::Value(left.value.clone()))
            } else if numerator == denominator {
                Ok(EvaluatedSignal::Value(right.value.clone()))
            } else {
                Err(SignalEvaluationError::SpatialOutsideExtent)
            }
        }
        SignalInterpolation::HoldPrevious => Ok(EvaluatedSignal::Value(left.value.clone())),
        SignalInterpolation::Nearest => Ok(EvaluatedSignal::Value(
            if numerator <= denominator - numerator {
                &left.value
            } else {
                &right.value
            }
            .clone(),
        )),
        SignalInterpolation::Linear { rounding, overflow } => {
            Ok(EvaluatedSignal::Value(interpolate_value(
                &left.value,
                &right.value,
                numerator,
                denominator,
                rounding,
                overflow,
            )?))
        }
    }
}

fn rational_coordinate(
    origin: i64,
    direction: i128,
    numerator: u64,
    denominator: u64,
) -> Result<i64, SignalEvaluationError> {
    let offset = direction
        .checked_mul(i128::from(numerator))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?
        / i128::from(denominator);
    i64::try_from(
        i128::from(origin)
            .checked_add(offset)
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
    )
    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)
}

fn sample_transmitter(
    transmitter: [i64; 3],
    distance_values: &[(u64, SignalValue)],
    orientation_values: &[([i64; 3], SignalValue)],
    environment_coefficients: &[ExactRatio],
    receiver: [i64; 3],
    orientation: Option<&EvaluatedSignal>,
    environment: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if environment.len() != environment_coefficients.len() {
        return Err(SignalEvaluationError::TypeMismatch);
    }
    let distance_squared = squared_distance(transmitter, receiver)?;
    let distance = u64::try_from(integer_square_root(
        distance_squared,
        SignalRounding::NearestTiesToEven,
    )?)
    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    let upper = distance_values.partition_point(|(candidate, _)| *candidate <= distance);
    let mut value = if upper == 0 {
        distance_values[0].1.clone()
    } else if upper == distance_values.len() {
        distance_values[distance_values.len() - 1].1.clone()
    } else {
        interpolate_value(
            &distance_values[upper - 1].1,
            &distance_values[upper].1,
            distance - distance_values[upper - 1].0,
            distance_values[upper].0 - distance_values[upper - 1].0,
            SignalRounding::NearestTiesToEven,
            SignalOverflow::Error,
        )?
    };
    let zero = ExactRatio::new(0, 1).map_err(SignalEvaluationError::Program)?;
    match (orientation, orientation_values.is_empty()) {
        (Some(orientation), false) => {
            let orientation = position_vector(orientation.value()?)?;
            let correction = orientation_values
                .iter()
                .min_by_key(|(candidate, _)| {
                    candidate
                        .iter()
                        .zip(orientation)
                        .map(|(candidate, actual)| {
                            let raw =
                                (i128::from(*candidate) - i128::from(actual)).rem_euclid(360_000);
                            raw.min(360_000 - raw).unsigned_abs()
                        })
                        .sum::<u128>()
                })
                .ok_or(SignalEvaluationError::TypeMismatch)?;
            value = arithmetic_values(&value, &correction.1, false, SignalOverflow::Error)?;
        }
        (None, true) => {}
        _ => return Err(SignalEvaluationError::TypeMismatch),
    }
    for (input, coefficient) in environment.iter().zip(environment_coefficients) {
        let contribution = scale_value(
            input.value()?,
            *coefficient,
            zero,
            SignalRounding::NearestTiesToEven,
            SignalOverflow::Error,
        )?;
        value = arithmetic_values(&value, &contribution, false, SignalOverflow::Error)?;
    }
    Ok(EvaluatedSignal::Value(value))
}

fn squared_distance(left: [i64; 3], right: [i64; 3]) -> Result<u128, SignalEvaluationError> {
    left.into_iter()
        .zip(right)
        .try_fold(0_u128, |total, (left, right)| {
            let delta = i128::from(left) - i128::from(right);
            delta
                .unsigned_abs()
                .checked_mul(delta.unsigned_abs())
                .and_then(|square| total.checked_add(square))
                .ok_or(SignalEvaluationError::ArithmeticOverflow)
        })
}

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
            [0; 3],
            [10; 3],
            [2, 1, 1],
            &[SignalValue::I64(1), SignalValue::I64(2)],
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
