//! Validates the actual signed metadata DAG before following any body reference.
//!
//! Native image inventories remain separate streamed artifact custody. These
//! rows cover only signed metadata, with retained bounded DFS workspace.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct Frame {
    row: usize,
    next_child: usize,
    height: usize,
}

impl NativeArchiveRecord {
    pub(super) fn authenticate_restored_metadata_dag_into(
        &self,
        attempt: &mut CompleteRestoredSettledArchiveValidationAttempt,
        additional: usize,
    ) -> Result<(), StateError> {
        let rows = &self.index.objects;
        if rows.is_empty()
            || rows.len() > self.limits.state.maximum_content_objects
            || rows
                .windows(2)
                .any(|pair| pair[0].reference >= pair[1].reference)
        {
            return Err(refused(
                "settled17 signed metadata roster is not closed and sorted",
            ));
        }
        let depth = self
            .limits
            .state
            .maximum_dependency_depth
            .checked_add(1)
            .ok_or_else(|| refused("settled17 metadata depth overflow"))?
            .min(rows.len());
        let colors = rows.len();
        let heights = rows
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or_else(|| refused("settled17 DAG height workspace overflow"))?;
        let stack = depth
            .checked_mul(std::mem::size_of::<Frame>())
            .ok_or_else(|| refused("settled17 DAG stack workspace overflow"))?;
        let work = colors
            .checked_add(heights)
            .and_then(|bytes| bytes.checked_add(stack))
            .ok_or_else(|| refused("settled17 DAG workspace overflow"))?;
        super::validation::admit(self, attempt, additional, work)?;
        attempt
            .dag_colors
            .try_reserve_exact(rows.len())
            .map_err(|_| refused("settled17 DAG color reserve"))?;
        attempt
            .dag_heights
            .try_reserve_exact(rows.len())
            .map_err(|_| refused("settled17 DAG height reserve"))?;
        attempt
            .dag_stack
            .try_reserve_exact(depth)
            .map_err(|_| refused("settled17 DAG stack reserve"))?;
        super::validation::admit(self, attempt, additional, 0)?;
        attempt.dag_colors.resize(rows.len(), 0);
        attempt.dag_heights.resize(rows.len(), 0);

        walk_admitted(
            rows,
            self.limits.state,
            depth,
            &mut attempt.dag_colors,
            &mut attempt.dag_heights,
            &mut attempt.dag_stack,
        )
    }
}

fn walk_admitted(
    rows: &[storage::Object],
    limits: crate::node_state::StateLimits,
    depth: usize,
    colors: &mut [u8],
    heights: &mut [usize],
    stack: &mut Vec<Frame>,
) -> Result<(), StateError> {
    if colors.len() != rows.len()
        || heights.len() != rows.len()
        || !stack.is_empty()
        || stack.capacity() < depth
    {
        return Err(refused(
            "settled17 DAG workspace differs from its admitted extent",
        ));
    }
    let mut edges = 0usize;
    for row in rows {
        if row.dependencies.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(refused(
                "settled17 metadata adjacency repeats or is unsorted",
            ));
        }
        edges = edges
            .checked_add(row.dependencies.len())
            .ok_or_else(|| refused("settled17 metadata edge count overflow"))?;
        if edges > limits.maximum_dependency_edges {
            return Err(refused("settled17 metadata edge limit"));
        }
    }
    for root in 0..rows.len() {
        if colors[root] != 0 {
            continue;
        }
        colors[root] = 1;
        stack.push(Frame {
            row: root,
            next_child: 0,
            height: 0,
        });
        while let Some(frame) = stack.last_mut() {
            let row = &rows[frame.row];
            let Some(child) = row.dependencies.get(frame.next_child) else {
                let completed = *frame;
                if completed.height > limits.maximum_dependency_depth {
                    return Err(refused("settled17 metadata dependency depth exhausted"));
                }
                colors[completed.row] = 2;
                heights[completed.row] = completed.height;
                stack.pop();
                if let Some(parent) = stack.last_mut() {
                    parent.height = parent.height.max(
                        completed
                            .height
                            .checked_add(1)
                            .ok_or_else(|| refused("settled17 metadata height overflow"))?,
                    );
                }
                continue;
            };
            frame.next_child += 1;
            let index = rows
                .binary_search_by(|candidate| candidate.reference.cmp(child))
                .map_err(|_| refused("settled17 metadata dependency has no signed body"))?;
            match colors[index] {
                0 => {
                    if stack.len() >= depth {
                        return Err(refused("settled17 metadata dependency depth exhausted"));
                    }
                    colors[index] = 1;
                    stack.push(Frame {
                        row: index,
                        next_child: 0,
                        height: 0,
                    });
                }
                1 => {
                    return Err(refused(
                        "settled17 immutable metadata graph contains a cycle",
                    ));
                }
                2 => {
                    frame.height = frame.height.max(
                        heights[index]
                            .checked_add(1)
                            .ok_or_else(|| refused("settled17 metadata height overflow"))?,
                    );
                }
                _ => return Err(refused("settled17 DAG validation state is invalid")),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_node_format::canonical;

    fn rows() -> Vec<storage::Object> {
        let mut references = [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ]
        .map(|bytes| canonical::content_ref(bytes, "application/octet-stream").unwrap());
        references.sort();
        vec![
            storage::Object {
                reference: references[0].clone(),
                dependencies: vec![references[1].clone()],
            },
            storage::Object {
                reference: references[1].clone(),
                dependencies: vec![references[2].clone()],
            },
            storage::Object {
                reference: references[2].clone(),
                dependencies: Vec::new(),
            },
        ]
    }

    fn check(rows: &[storage::Object], depth: usize) -> Result<(), StateError> {
        let mut limits = crate::node_state::StateLimits::default();
        limits.maximum_dependency_depth = depth;
        let mut colors = vec![0; rows.len()];
        let mut heights = vec![0; rows.len()];
        let mut stack = Vec::with_capacity(rows.len());
        walk_admitted(
            rows,
            limits,
            depth.checked_add(1).unwrap().min(rows.len()),
            &mut colors,
            &mut heights,
            &mut stack,
        )
    }

    #[test]
    fn signed_metadata_walk_preserves_shared_ancestry_and_refuses_cycle_or_missing_body() {
        let mut rows = rows();
        assert!(check(&rows, 2).is_ok());
        assert!(check(&rows, 1).is_err());

        let cycle = rows[0].reference.clone();
        rows[2].dependencies.push(cycle);
        assert!(check(&rows, 3).is_err());

        rows[2].dependencies[0] =
            canonical::content_ref(b"absent", "application/octet-stream").unwrap();
        assert!(check(&rows, 3).is_err());
    }
}
