//! Exact sampling of normalized spatial artifacts.

use super::*;

/// Evaluates one normalized spatial source from the production DAG store.
pub(in crate::model::fault_signal) fn evaluate_normalized_spatial_source(
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
                RegularGrid {
                    origin: *origin_mm,
                    cell: *cell_size_mm,
                    dimensions: *dimensions,
                    values,
                },
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

pub(super) fn sample_point_set(
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

pub(super) fn simplex_is_degenerate(samples: &[SpatialSample], simplex: &SpatialSimplex) -> bool {
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

#[derive(Clone, Copy)]
pub(super) struct RegularGrid<'a> {
    pub(super) origin: [i64; 3],
    pub(super) cell: [u64; 3],
    pub(super) dimensions: [u32; 3],
    pub(super) values: &'a [SignalValue],
}

pub(super) fn sample_regular_grid(
    grid: RegularGrid<'_>,
    position: [i64; 3],
    interpolation: SignalInterpolation,
    outside: &SignalBoundaryBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let mut lower = [0_u32; 3];
    let mut remainder = [0_u64; 3];
    for axis in 0..3 {
        let offset = i128::from(position[axis]) - i128::from(grid.origin[axis]);
        if offset < 0 {
            return evaluate_boundary(outside, grid.values.first(), None);
        }
        let cell_i128 = i128::from(grid.cell[axis]);
        let final_extent = cell_i128
            .checked_mul(i128::from(grid.dimensions[axis] - 1))
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        if offset > final_extent {
            return evaluate_boundary(outside, grid.values.last(), None);
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
            EvaluatedSignal::Value(grid_value(grid.dimensions, grid.values, lower)?.clone()),
        ),
        SignalInterpolation::Nearest => {
            let mut nearest = lower;
            for (axis, numerator) in remainder.iter().copied().enumerate() {
                if numerator > grid.cell[axis] / 2 && nearest[axis] + 1 < grid.dimensions[axis] {
                    nearest[axis] += 1;
                }
            }
            Ok(EvaluatedSignal::Value(
                grid_value(grid.dimensions, grid.values, nearest)?.clone(),
            ))
        }
        SignalInterpolation::Linear { rounding, overflow } => {
            let mut current = values_for_cube(grid.dimensions, grid.values, lower)?;
            for (axis, numerator) in remainder.iter().copied().enumerate() {
                let mut next = Vec::with_capacity(current.len() / 2);
                let (pairs, unpaired) = current.as_chunks::<2>();
                if !unpaired.is_empty() {
                    return Err(SignalEvaluationError::TypeMismatch);
                }
                for pair in pairs {
                    next.push(interpolate_value(
                        &pair[0],
                        &pair[1],
                        numerator,
                        grid.cell[axis],
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
        RegularGrid {
            origin: *origin_mm,
            cell: *cell_size_mm,
            dimensions: *dimensions,
            values,
        },
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
