//! Borrowed predicate formatting for bounded canonical lexical sorting keys.
//!
//! Composite predicates recurse into borrowed children. UTF-8 names and binary
//! frame patterns are emitted directly, without temporary owned fragments.

use super::world_stream::Hex;
use super::*;
use std::fmt::{self, Display};

pub(in crate::model) struct PredicateMaterial<'a>(pub(in crate::model) &'a Predicate);

impl Display for PredicateMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Predicate::At { at } => write!(output, "predicate=at\nat_ticks={}", at.ticks),
            Predicate::After { duration, of } => write!(
                output,
                "predicate=after\nduration_ticks={}\n{}",
                duration.ticks,
                Name("event_id", &of.name)
            ),
            Predicate::Timer { name } => {
                write!(output, "predicate=timer\n{}", Name("timer_id", &name.name))
            }
            Predicate::NetworkMatch { link, predicate } => {
                output.write_str("predicate=network-match\n")?;
                match link {
                    Some(link) => {
                        write!(output, "network_link=some\n{}", Name("link_id", &link.name))?
                    }
                    None => output.write_str("network_link=any")?,
                }
                write!(output, "\n{}", FrameMaterial(predicate))
            }
            Predicate::ConsoleMatch { node, regex } => write!(
                output,
                "predicate=console-match\n{}\nregex_len={}\nregex={}",
                Name("console_node", &node.name),
                regex.pattern().len(),
                regex.pattern()
            ),
            Predicate::CoveragePoint { node, point } => {
                write!(
                    output,
                    "predicate=coverage-point\n{}\n",
                    Name("coverage_node", &node.name)
                )?;
                match point {
                    CodePoint::GuestAddress { address } => {
                        write!(output, "code_point=guest-address\ncode_address={address}")
                    }
                    CodePoint::Symbol { name } => {
                        write!(output, "code_point=symbol\n{}", Name("symbol", name))
                    }
                }
            }
            Predicate::MemoryPredicate {
                node,
                place,
                cmp,
                value,
            } => write!(
                output,
                "predicate=memory-predicate\n{}\n{}\nmemory_cmp={}\nmemory_value={value}",
                Name("memory_node", &node.name),
                PlaceMaterial(place),
                memory_cmp_label(*cmp)
            ),
            Predicate::IoPattern { node, kind } => write!(
                output,
                "predicate=io-pattern\n{}\nio_kind={}",
                Name("io_node", &node.name),
                io_event_kind_label(*kind)
            ),
            Predicate::NodeState { node, state } => write!(
                output,
                "predicate=node-state\n{}\nnode_lifecycle={}",
                Name("lifecycle_node", &node.name),
                node_lifecycle_label(*state)
            ),
            Predicate::AssertionState { name, state } => write!(
                output,
                "predicate=assertion-state\n{}\nassertion_phase={}",
                Name("assertion_id", &name.name),
                assertion_phase_label(*state)
            ),
            Predicate::Quiescent => output.write_str("predicate=quiescent"),
            Predicate::Named { name, nodes } => {
                write!(
                    output,
                    "predicate=named\n{}\npredicate_nodes={}",
                    Name("predicate_name", name),
                    nodes.len()
                )?;
                for node in nodes {
                    write!(output, "\n{}", Name("predicate_node", &node.name))?;
                }
                Ok(())
            }
            Predicate::GuestMarker { marker } => write!(
                output,
                "predicate=guest-marker\n{}",
                Name("marker_id", &marker.name)
            ),
            Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
                let kind = if matches!(self.0, Predicate::AllOf { .. }) {
                    "all-of"
                } else {
                    "any-of"
                };
                write!(output, "predicate={kind}\npredicates={}", predicates.len())?;
                for predicate in predicates {
                    write!(output, "\n{}", PredicateMaterial(predicate))?;
                }
                Ok(())
            }
            Predicate::Once { predicate } => {
                write!(output, "predicate=once\n{}", PredicateMaterial(predicate))
            }
            Predicate::Not { predicate } => {
                write!(output, "predicate=not\n{}", PredicateMaterial(predicate))
            }
        }
    }
}

pub(super) struct Name<'a>(pub(super) &'a str, pub(super) &'a str);

impl Display for Name<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{}_len={}\n{}={}",
            self.0,
            self.1.len(),
            self.0,
            self.1
        )
    }
}

struct FrameMaterial<'a>(&'a FramePredicate);

impl Display for FrameMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, field, bytes) = match self.0 {
            FramePredicate::Any => return output.write_str("frame_predicate=any"),
            FramePredicate::Exact(bytes) => ("exact", "frame_bytes", bytes),
            FramePredicate::Contains(bytes) => ("contains", "frame_needle", bytes),
            FramePredicate::Prefix(bytes) => ("prefix", "frame_prefix", bytes),
        };
        write!(
            output,
            "frame_predicate={kind}\n{field}_len={}\n{field}={}",
            bytes.len(),
            Hex(bytes)
        )
    }
}

struct PlaceMaterial<'a>(&'a MemPlace);

impl Display for PlaceMaterial<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = match self.0 {
            MemPlace::PhysicalAddress { address, width } => {
                write!(output, "mem_place=physical-address\nmem_address={address}")?;
                width
            }
            MemPlace::VirtualAddress { address, width } => {
                write!(output, "mem_place=virtual-address\nmem_address={address}")?;
                width
            }
            MemPlace::Symbol { name, width } => {
                write!(output, "mem_place=symbol\n{}", Name("symbol", name))?;
                width
            }
            MemPlace::Register { name, width } => {
                write!(output, "mem_place=register\n{}", Name("register", name))?;
                width
            }
        };
        write!(output, "\nmem_width={}", memory_width_label(*width))
    }
}
