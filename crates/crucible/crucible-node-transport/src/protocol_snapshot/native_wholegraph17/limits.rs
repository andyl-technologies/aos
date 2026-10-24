//! Enforces independently admitted node and nesting axes before field walking.

use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::invalid;

/// Carries explicit parser axes and remaining actual target-backing credit.
#[derive(Clone, Copy)]
pub(crate) struct NativeCurrentGraph17ReadLimits {
    /// Bounds actual retained raw, scratch and selected typed backing together.
    pub(crate) maximum_requested: usize,
    /// Independently bounds selected typed backing, excluding raw/scratch banks.
    pub(crate) maximum_target_requested: usize,
    /// Bounds every JSON value and object-key token in the complete wire.
    pub(crate) maximum_nodes: usize,
    /// Bounds container nesting, including immutable evidence; at most 64.
    pub(crate) maximum_depth: usize,
}

impl NativeCurrentGraph17ReadLimits {
    /// Checks all wire tokens before any selected typed allocation begins.
    ///
    /// This pass enforces resource axes. The following complete known-field
    /// grammar remains responsible for lexical and semantic JSON validation.
    ///
    /// # Errors
    /// Refuses zero limits, excessive nesting, mismatched containers, truncated
    /// strings or node demand beyond the independently admitted ceiling.
    pub(crate) fn authenticate_wire_data(self, input: &[u8]) -> Result<(), ProviderError> {
        if self.maximum_nodes == 0 || self.maximum_depth == 0 || self.maximum_depth > 64 {
            return Err(invalid());
        }
        let mut containers = [0u8; 64];
        let mut depth = 0usize;
        let mut nodes = 0usize;
        let mut position = 0usize;
        while let Some(&byte) = input.get(position) {
            match byte {
                b' ' | b'\t' | b'\r' | b'\n' | b',' | b':' => position += 1,
                b'[' | b'{' => {
                    charge_node(&mut nodes, self.maximum_nodes)?;
                    if depth == self.maximum_depth {
                        return Err(invalid());
                    }
                    containers[depth] = byte;
                    depth += 1;
                    position += 1;
                }
                b']' | b'}' => {
                    depth = depth.checked_sub(1).ok_or_else(invalid)?;
                    if (containers[depth], byte) != (b'[', b']')
                        && (containers[depth], byte) != (b'{', b'}')
                    {
                        return Err(invalid());
                    }
                    position += 1;
                }
                b'"' => {
                    charge_node(&mut nodes, self.maximum_nodes)?;
                    position += 1;
                    loop {
                        match input.get(position).copied().ok_or_else(invalid)? {
                            b'"' => {
                                position += 1;
                                break;
                            }
                            b'\\' => {
                                // The strict grammar checks the escape itself;
                                // skipping its following byte keeps quotes inert.
                                position = position.checked_add(2).ok_or_else(invalid)?;
                                if position > input.len() {
                                    return Err(invalid());
                                }
                            }
                            byte if byte < 0x20 => return Err(invalid()),
                            _ => position += 1,
                        }
                    }
                }
                b'-' | b'0'..=b'9' | b't' | b'f' | b'n' => {
                    charge_node(&mut nodes, self.maximum_nodes)?;
                    position += 1;
                    while input.get(position).is_some_and(|byte| {
                        !matches!(
                            byte,
                            b' ' | b'\t' | b'\r' | b'\n' | b',' | b':' | b']' | b'}'
                        )
                    }) {
                        position += 1;
                    }
                }
                _ => return Err(invalid()),
            }
        }
        if depth != 0 || nodes == 0 {
            return Err(invalid());
        }
        Ok(())
    }
}

fn charge_node(nodes: &mut usize, maximum: usize) -> Result<(), ProviderError> {
    *nodes = nodes.checked_add(1).ok_or_else(invalid)?;
    if *nodes > maximum {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_node_axis_counts_keys_and_immutable_children() {
        let limits = NativeCurrentGraph17ReadLimits {
            maximum_requested: 1024,
            maximum_target_requested: 1024,
            maximum_nodes: 4,
            maximum_depth: 4,
        };
        assert!(limits.authenticate_wire_data(br#"{"a":[true]}"#).is_ok());
        assert!(
            limits
                .authenticate_wire_data(br#"{"a":[true,false]}"#)
                .is_err()
        );
    }

    #[test]
    fn quoted_brackets_and_escaped_quotes_do_not_change_depth() {
        let limits = NativeCurrentGraph17ReadLimits {
            maximum_requested: 1024,
            maximum_target_requested: 1024,
            maximum_nodes: 2,
            maximum_depth: 1,
        };
        assert!(limits.authenticate_wire_data(br#"["[\"}"]"#).is_ok());
        assert!(limits.authenticate_wire_data(b"[[]]").is_err());
        assert!(limits.authenticate_wire_data(b"[{]").is_err());
    }
}
