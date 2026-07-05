//! Per-element binary encoders, decoders, tag tables, and the [`BinaryReader`].
//!
//! These helpers serialize the individual building blocks of a parse-cache
//! artifact — AST and IR nodes, their payloads, frames, slices, and the
//! enum-to-`u8` tag mappings — and read them back. The little-endian framing is
//! consumed by the top-level serializers in [`mod@format`].

use super::*;

pub(super) fn encode_ir_node(out: &mut Vec<u8>, node: IrNode) {
    out.push(ir_kind_tag(node.kind));
    write_u32(out, node.span.start);
    write_u32(out, node.span.end);
    out.push(effect_class_tag(node.effect));
    encode_ir_data(out, node.data);
}

pub(super) fn decode_ir_node(reader: &mut BinaryReader<'_>) -> Result<IrNode, String> {
    let kind = decode_ir_kind(reader.read_u8()?)?;
    let span = Span::new(reader.read_u32()?, reader.read_u32()?);
    let effect = decode_effect_class(reader.read_u8()?)?;
    let data = decode_ir_data(reader)?;
    Ok(IrNode::new(kind, span, effect, data))
}

pub(super) fn encode_ir_data(out: &mut Vec<u8>, data: IrData) {
    match data {
        IrData::None => out.push(0),
        IrData::Int(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        IrData::Float(value) => {
            out.push(2);
            out.extend_from_slice(&value.to_le_bytes());
        }
        IrData::Bool(value) => {
            out.push(3);
            out.push(u8::from(value));
        }
        IrData::Symbol(symbol) => {
            out.push(4);
            write_u32(out, symbol.as_u32());
        }
        IrData::GlobalVar { site, symbol } => {
            out.push(26);
            write_u32(out, site.as_u32());
            write_u32(out, symbol.as_u32());
        }
        IrData::SearchPath {
            literal,
            search_path,
        } => {
            out.push(25);
            write_u32(out, literal.as_u32());
            encode_option_u32(out, search_path.map(IrId::as_u32));
        }
        IrData::Node(node) => {
            out.push(5);
            write_u32(out, node.as_u32());
        }
        IrData::Pair { first, second } => {
            out.push(6);
            write_u32(out, first.as_u32());
            write_u32(out, second.as_u32());
        }
        IrData::Triple {
            first,
            second,
            third,
        } => {
            out.push(7);
            write_u32(out, first.as_u32());
            write_u32(out, second.as_u32());
            write_u32(out, third.as_u32());
        }
        IrData::Children(slice) => {
            out.push(8);
            encode_ir_child_slice(out, slice);
        }
        IrData::Bindings(slice) => {
            out.push(9);
            encode_ir_binding_slice(out, slice);
        }
        IrData::Binary { op, lhs, rhs } => {
            out.push(10);
            out.push(bin_op_tag(op));
            write_u32(out, lhs.as_u32());
            write_u32(out, rhs.as_u32());
        }
        IrData::Unary { op, operand } => {
            out.push(11);
            out.push(unary_op_tag(op));
            write_u32(out, operand.as_u32());
        }
        IrData::Select {
            site,
            receiver,
            path,
            default,
        } => {
            out.push(12);
            write_u32(out, site.as_u32());
            write_u32(out, receiver.as_u32());
            write_u32(out, path.as_u32());
            encode_option_u32(out, default.map(IrId::as_u32));
        }
        IrData::HasAttr {
            site,
            receiver,
            path,
        } => {
            out.push(13);
            write_u32(out, site.as_u32());
            write_u32(out, receiver.as_u32());
            write_u32(out, path.as_u32());
        }
        IrData::PrimOp { symbol, args } => {
            out.push(14);
            write_u32(out, symbol.as_u32());
            encode_ir_child_slice(out, args);
        }
        IrData::DialectNode { op, argument } => {
            out.push(23);
            write_u32(out, u32::from(op.as_u16()));
            write_u32(out, argument.as_u32());
        }
        IrData::DialectScopeVar {
            op,
            site,
            symbol,
            chain,
        } => {
            out.push(24);
            write_u32(out, u32::from(op.as_u16()));
            write_u32(out, site.as_u32());
            write_u32(out, symbol.as_u32());
            write_u32(out, chain);
        }
        IrData::Lambda {
            pattern,
            body,
            frame,
        } => {
            out.push(15);
            write_u32(out, pattern.as_u32());
            write_u32(out, body.as_u32());
            encode_option_u32(out, frame.map(FrameId::as_u32));
        }
        IrData::Let {
            bindings,
            body,
            frame,
        } => {
            out.push(16);
            encode_ir_binding_slice(out, bindings);
            write_u32(out, body.as_u32());
            encode_option_u32(out, frame.map(FrameId::as_u32));
        }
        IrData::AttrSet {
            shape,
            bindings,
            recursive,
            has_dynamic,
            frame,
        } => {
            out.push(17);
            write_u32(out, shape.as_u32());
            encode_ir_binding_slice(out, bindings);
            out.push(u8::from(recursive));
            out.push(u8::from(has_dynamic));
            encode_option_u32(out, frame.map(FrameId::as_u32));
        }
        IrData::FormalSet {
            formals,
            ellipsis,
            alias,
        } => {
            out.push(18);
            encode_ir_child_slice(out, formals);
            out.push(u8::from(ellipsis));
            encode_option_u32(out, alias.map(Symbol::as_u32));
        }
        IrData::Formal { name, default } => {
            out.push(19);
            write_u32(out, name.as_u32());
            encode_option_u32(out, default.map(IrId::as_u32));
        }
        IrData::Local { slot } => {
            out.push(20);
            write_u32(out, slot);
        }
        IrData::Upval { depth, slot } => {
            out.push(21);
            write_u32(out, depth);
            write_u32(out, slot);
        }
    }
}

pub(super) fn decode_ir_data(reader: &mut BinaryReader<'_>) -> Result<IrData, String> {
    let tag = reader.read_u8()?;
    match tag {
        0 => Ok(IrData::None),
        1 => Ok(IrData::Int(reader.read_i64()?)),
        2 => Ok(IrData::Float(reader.read_f64()?)),
        3 => Ok(IrData::Bool(reader.read_bool()?)),
        4 => Ok(IrData::Symbol(Symbol::new(reader.read_u32()?))),
        26 => Ok(IrData::GlobalVar {
            site: IrInlineCacheSiteId::new(reader.read_u32()?),
            symbol: Symbol::new(reader.read_u32()?),
        }),
        25 => Ok(IrData::SearchPath {
            literal: Symbol::new(reader.read_u32()?),
            search_path: reader.read_option_u32()?.map(IrId::new),
        }),
        5 => Ok(IrData::Node(IrId::new(reader.read_u32()?))),
        6 => Ok(IrData::Pair {
            first: IrId::new(reader.read_u32()?),
            second: IrId::new(reader.read_u32()?),
        }),
        7 => Ok(IrData::Triple {
            first: IrId::new(reader.read_u32()?),
            second: IrId::new(reader.read_u32()?),
            third: IrId::new(reader.read_u32()?),
        }),
        8 => Ok(IrData::Children(decode_ir_child_slice(reader)?)),
        9 => Ok(IrData::Bindings(decode_ir_binding_slice(reader)?)),
        10 => Ok(IrData::Binary {
            op: decode_bin_op(reader.read_u8()?)?,
            lhs: IrId::new(reader.read_u32()?),
            rhs: IrId::new(reader.read_u32()?),
        }),
        11 => Ok(IrData::Unary {
            op: decode_unary_op(reader.read_u8()?)?,
            operand: IrId::new(reader.read_u32()?),
        }),
        12 => Ok(IrData::Select {
            site: IrInlineCacheSiteId::new(reader.read_u32()?),
            receiver: IrId::new(reader.read_u32()?),
            path: IrAttrPathId::new(reader.read_u32()?),
            default: reader.read_option_u32()?.map(IrId::new),
        }),
        13 => Ok(IrData::HasAttr {
            site: IrInlineCacheSiteId::new(reader.read_u32()?),
            receiver: IrId::new(reader.read_u32()?),
            path: IrAttrPathId::new(reader.read_u32()?),
        }),
        14 => Ok(IrData::PrimOp {
            symbol: Symbol::new(reader.read_u32()?),
            args: decode_ir_child_slice(reader)?,
        }),
        15 => Ok(IrData::Lambda {
            pattern: IrId::new(reader.read_u32()?),
            body: IrId::new(reader.read_u32()?),
            frame: reader.read_option_u32()?.map(FrameId::new),
        }),
        16 => Ok(IrData::Let {
            bindings: decode_ir_binding_slice(reader)?,
            body: IrId::new(reader.read_u32()?),
            frame: reader.read_option_u32()?.map(FrameId::new),
        }),
        17 => Ok(IrData::AttrSet {
            shape: IrShapeId::new(reader.read_u32()?),
            bindings: decode_ir_binding_slice(reader)?,
            recursive: reader.read_bool()?,
            has_dynamic: reader.read_bool()?,
            frame: reader.read_option_u32()?.map(FrameId::new),
        }),
        18 => Ok(IrData::FormalSet {
            formals: decode_ir_child_slice(reader)?,
            ellipsis: reader.read_bool()?,
            alias: reader.read_option_u32()?.map(Symbol::new),
        }),
        19 => Ok(IrData::Formal {
            name: Symbol::new(reader.read_u32()?),
            default: reader.read_option_u32()?.map(IrId::new),
        }),
        20 => Ok(IrData::Local {
            slot: reader.read_u32()?,
        }),
        21 => Ok(IrData::Upval {
            depth: reader.read_u32()?,
            slot: reader.read_u32()?,
        }),
        23 => Ok(IrData::DialectNode {
            op: decode_ir_dialect_op(reader.read_u32()?)?,
            argument: IrId::new(reader.read_u32()?),
        }),
        24 => Ok(IrData::DialectScopeVar {
            op: decode_ir_dialect_op(reader.read_u32()?)?,
            site: IrInlineCacheSiteId::new(reader.read_u32()?),
            symbol: Symbol::new(reader.read_u32()?),
            chain: reader.read_u32()?,
        }),
        tag => Err(format!("invalid IR data tag {tag}")),
    }
}

pub(super) fn encode_ir_attr_path_segment(out: &mut Vec<u8>, segment: IrAttrPathSegment) {
    match segment {
        IrAttrPathSegment::Static(symbol) => {
            out.push(0);
            write_u32(out, symbol.as_u32());
        }
        IrAttrPathSegment::Dynamic(node) => {
            out.push(1);
            write_u32(out, node.as_u32());
        }
    }
}

pub(super) fn decode_ir_attr_path_segment(
    reader: &mut BinaryReader<'_>,
) -> Result<IrAttrPathSegment, String> {
    match reader.read_u8()? {
        0 => Ok(IrAttrPathSegment::Static(Symbol::new(reader.read_u32()?))),
        1 => Ok(IrAttrPathSegment::Dynamic(IrId::new(reader.read_u32()?))),
        tag => Err(format!("invalid IR attr-path segment tag {tag}")),
    }
}

pub(super) fn encode_ir_child_slice(out: &mut Vec<u8>, slice: IrChildSlice) {
    write_u32(out, slice.start);
    write_u32(out, slice.len);
}

pub(super) fn decode_ir_child_slice(reader: &mut BinaryReader<'_>) -> Result<IrChildSlice, String> {
    Ok(IrChildSlice::new(reader.read_u32()?, reader.read_u32()?))
}

pub(super) fn encode_ir_binding_slice(out: &mut Vec<u8>, slice: IrBindingSlice) {
    write_u32(out, slice.start);
    write_u32(out, slice.len);
}

pub(super) fn decode_ir_binding_slice(
    reader: &mut BinaryReader<'_>,
) -> Result<IrBindingSlice, String> {
    Ok(IrBindingSlice::new(reader.read_u32()?, reader.read_u32()?))
}

pub(super) fn encode_node(out: &mut Vec<u8>, node: Node) {
    out.push(node_kind_tag(node.kind));
    write_u32(out, node.span.start);
    write_u32(out, node.span.end);
    encode_node_data(out, node.data);
}

pub(super) fn decode_node(reader: &mut BinaryReader<'_>) -> Result<Node, String> {
    let kind = decode_node_kind(reader.read_u8()?)?;
    let span = Span::new(reader.read_u32()?, reader.read_u32()?);
    let data = decode_node_data(reader)?;
    Ok(Node::new(kind, span, data))
}

pub(super) fn encode_node_data(out: &mut Vec<u8>, data: NodeData) {
    match data {
        NodeData::None => out.push(0),
        NodeData::Int(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        NodeData::Float(value) => {
            out.push(2);
            out.extend_from_slice(&value.to_le_bytes());
        }
        NodeData::Symbol(symbol) => {
            out.push(3);
            write_u32(out, symbol.as_u32());
        }
        NodeData::SearchPath {
            literal,
            search_path,
        } => {
            out.push(20);
            write_u32(out, literal.as_u32());
            encode_option_u32(out, search_path.map(NodeId::as_u32));
        }
        NodeData::Node(node) => {
            out.push(4);
            write_u32(out, node.as_u32());
        }
        NodeData::Pair { first, second } => {
            out.push(5);
            write_u32(out, first.as_u32());
            write_u32(out, second.as_u32());
        }
        NodeData::Triple {
            first,
            second,
            third,
        } => {
            out.push(6);
            write_u32(out, first.as_u32());
            write_u32(out, second.as_u32());
            write_u32(out, third.as_u32());
        }
        NodeData::Children(slice) => {
            out.push(7);
            encode_child_slice(out, slice);
        }
        NodeData::Binary { op, lhs, rhs } => {
            out.push(8);
            out.push(bin_op_tag(op));
            write_u32(out, lhs.as_u32());
            write_u32(out, rhs.as_u32());
        }
        NodeData::Unary { op, operand } => {
            out.push(9);
            out.push(unary_op_tag(op));
            write_u32(out, operand.as_u32());
        }
        NodeData::Select {
            receiver,
            path,
            default,
        } => {
            out.push(10);
            write_u32(out, receiver.as_u32());
            encode_child_slice(out, path);
            encode_option_u32(out, default.map(NodeId::as_u32));
        }
        NodeData::HasAttr { receiver, path } => {
            out.push(11);
            write_u32(out, receiver.as_u32());
            encode_child_slice(out, path);
        }
        NodeData::Binding { path, value } => {
            out.push(12);
            encode_child_slice(out, path);
            write_u32(out, value.as_u32());
        }
        NodeData::LetIn { bindings, body } => {
            out.push(13);
            encode_child_slice(out, bindings);
            write_u32(out, body.as_u32());
        }
        NodeData::Inherit { from, names } => {
            out.push(14);
            encode_option_u32(out, from.map(NodeId::as_u32));
            encode_child_slice(out, names);
        }
        NodeData::FormalSet {
            formals,
            ellipsis,
            alias,
        } => {
            out.push(15);
            encode_child_slice(out, formals);
            out.push(u8::from(ellipsis));
            encode_option_u32(out, alias.map(Symbol::as_u32));
        }
        NodeData::Formal { name, default } => {
            out.push(16);
            write_u32(out, name.as_u32());
            encode_option_u32(out, default.map(NodeId::as_u32));
        }
        NodeData::Local { slot } => {
            out.push(17);
            write_u32(out, slot);
        }
        NodeData::Upval { depth, slot } => {
            out.push(18);
            write_u32(out, depth);
            write_u32(out, slot);
        }
        NodeData::WithVar { symbol, chain } => {
            out.push(19);
            write_u32(out, symbol.as_u32());
            write_u32(out, chain);
        }
    }
}

pub(super) fn decode_node_data(reader: &mut BinaryReader<'_>) -> Result<NodeData, String> {
    let tag = reader.read_u8()?;
    match tag {
        0 => Ok(NodeData::None),
        1 => Ok(NodeData::Int(reader.read_i64()?)),
        2 => Ok(NodeData::Float(reader.read_f64()?)),
        3 => Ok(NodeData::Symbol(Symbol::new(reader.read_u32()?))),
        20 => Ok(NodeData::SearchPath {
            literal: Symbol::new(reader.read_u32()?),
            search_path: reader.read_option_u32()?.map(NodeId::new),
        }),
        4 => Ok(NodeData::Node(NodeId::new(reader.read_u32()?))),
        5 => Ok(NodeData::Pair {
            first: NodeId::new(reader.read_u32()?),
            second: NodeId::new(reader.read_u32()?),
        }),
        6 => Ok(NodeData::Triple {
            first: NodeId::new(reader.read_u32()?),
            second: NodeId::new(reader.read_u32()?),
            third: NodeId::new(reader.read_u32()?),
        }),
        7 => Ok(NodeData::Children(decode_child_slice(reader)?)),
        8 => Ok(NodeData::Binary {
            op: decode_bin_op(reader.read_u8()?)?,
            lhs: NodeId::new(reader.read_u32()?),
            rhs: NodeId::new(reader.read_u32()?),
        }),
        9 => Ok(NodeData::Unary {
            op: decode_unary_op(reader.read_u8()?)?,
            operand: NodeId::new(reader.read_u32()?),
        }),
        10 => Ok(NodeData::Select {
            receiver: NodeId::new(reader.read_u32()?),
            path: decode_child_slice(reader)?,
            default: reader.read_option_u32()?.map(NodeId::new),
        }),
        11 => Ok(NodeData::HasAttr {
            receiver: NodeId::new(reader.read_u32()?),
            path: decode_child_slice(reader)?,
        }),
        12 => Ok(NodeData::Binding {
            path: decode_child_slice(reader)?,
            value: NodeId::new(reader.read_u32()?),
        }),
        13 => Ok(NodeData::LetIn {
            bindings: decode_child_slice(reader)?,
            body: NodeId::new(reader.read_u32()?),
        }),
        14 => Ok(NodeData::Inherit {
            from: reader.read_option_u32()?.map(NodeId::new),
            names: decode_child_slice(reader)?,
        }),
        15 => Ok(NodeData::FormalSet {
            formals: decode_child_slice(reader)?,
            ellipsis: reader.read_bool()?,
            alias: reader.read_option_u32()?.map(Symbol::new),
        }),
        16 => Ok(NodeData::Formal {
            name: Symbol::new(reader.read_u32()?),
            default: reader.read_option_u32()?.map(NodeId::new),
        }),
        17 => Ok(NodeData::Local {
            slot: reader.read_u32()?,
        }),
        18 => Ok(NodeData::Upval {
            depth: reader.read_u32()?,
            slot: reader.read_u32()?,
        }),
        19 => Ok(NodeData::WithVar {
            symbol: Symbol::new(reader.read_u32()?),
            chain: reader.read_u32()?,
        }),
        tag => Err(format!("invalid node data tag {tag}")),
    }
}

pub(super) fn encode_frame(out: &mut Vec<u8>, frame: &FrameInfo) -> Result<(), ParseCacheError> {
    write_u32(out, frame.slot_count);
    out.push(u8::from(frame.rec));
    out.push(u8::from(frame.has_with));
    write_len(out, frame.captures.len(), "frame capture count")?;
    for capture in frame.captures.as_ref() {
        out.extend_from_slice(&capture.depth.to_le_bytes());
        out.extend_from_slice(&capture.slot.to_le_bytes());
    }
    Ok(())
}

pub(super) fn decode_frame(reader: &mut BinaryReader<'_>) -> Result<FrameInfo, String> {
    let slot_count = reader.read_u32()?;
    let rec = reader.read_bool()?;
    let has_with = reader.read_bool()?;
    let capture_count = reader.read_len("frame capture count")?;
    let mut captures = Vec::with_capacity(capture_count);
    for _ in 0..capture_count {
        captures.push(Upvalue {
            depth: reader.read_u16()?,
            slot: reader.read_u16()?,
        });
    }
    Ok(FrameInfo {
        slot_count,
        captures: captures.into_boxed_slice(),
        rec,
        has_with,
    })
}

pub(super) fn encode_child_slice(out: &mut Vec<u8>, slice: ChildSlice) {
    write_u32(out, slice.start);
    write_u32(out, slice.len);
}

pub(super) fn decode_child_slice(reader: &mut BinaryReader<'_>) -> Result<ChildSlice, String> {
    Ok(ChildSlice::new(reader.read_u32()?, reader.read_u32()?))
}

pub(super) fn encode_option_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u32(out, value);
        }
        None => out.push(0),
    }
}

pub(super) fn encode_option_span(out: &mut Vec<u8>, value: Option<Span>) {
    match value {
        Some(value) => {
            out.push(1);
            write_u32(out, value.start);
            write_u32(out, value.end);
        }
        None => out.push(0),
    }
}

pub(super) fn write_len(
    out: &mut Vec<u8>,
    len: usize,
    what: &'static str,
) -> Result<(), ParseCacheError> {
    let len = u32::try_from(len)
        .map_err(|_| ParseCacheError::EncodeArtifact(format!("{what} exceeds u32")))?;
    write_u32(out, len);
    Ok(())
}

pub(super) fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn ir_kind_tag(kind: IrKind) -> u8 {
    match kind {
        IrKind::Int => 0,
        IrKind::Float => 1,
        IrKind::Bool => 2,
        IrKind::Null => 3,
        IrKind::Str => 4,
        IrKind::Path => 5,
        IrKind::SearchPath => 6,
        IrKind::Uri => 7,
        IrKind::LocalVar => 8,
        IrKind::UpvalVar => 9,
        IrKind::GlobalVar => 10,
        IrKind::List => 12,
        IrKind::AttrSet => 13,
        IrKind::Lambda => 14,
        IrKind::FormalSet => 15,
        IrKind::Formal => 16,
        IrKind::Apply => 17,
        IrKind::Select => 18,
        IrKind::HasAttr => 19,
        IrKind::Let => 20,
        IrKind::With => 21,
        IrKind::Assert => 22,
        IrKind::If => 23,
        IrKind::BinOp => 24,
        IrKind::UnaryOp => 25,
        IrKind::Interp => 26,
        IrKind::ThunkAlloc => 27,
        IrKind::PrimOp => 28,
        IrKind::BuiltinAttr => 30,
    }
}

pub(super) fn decode_ir_kind(tag: u8) -> Result<IrKind, String> {
    match tag {
        0 => Ok(IrKind::Int),
        1 => Ok(IrKind::Float),
        2 => Ok(IrKind::Bool),
        3 => Ok(IrKind::Null),
        4 => Ok(IrKind::Str),
        5 => Ok(IrKind::Path),
        6 => Ok(IrKind::SearchPath),
        7 => Ok(IrKind::Uri),
        8 => Ok(IrKind::LocalVar),
        9 => Ok(IrKind::UpvalVar),
        10 => Ok(IrKind::GlobalVar),
        12 => Ok(IrKind::List),
        13 => Ok(IrKind::AttrSet),
        14 => Ok(IrKind::Lambda),
        15 => Ok(IrKind::FormalSet),
        16 => Ok(IrKind::Formal),
        17 => Ok(IrKind::Apply),
        18 => Ok(IrKind::Select),
        19 => Ok(IrKind::HasAttr),
        20 => Ok(IrKind::Let),
        21 => Ok(IrKind::With),
        22 => Ok(IrKind::Assert),
        23 => Ok(IrKind::If),
        24 => Ok(IrKind::BinOp),
        25 => Ok(IrKind::UnaryOp),
        26 => Ok(IrKind::Interp),
        27 => Ok(IrKind::ThunkAlloc),
        28 => Ok(IrKind::PrimOp),
        30 => Ok(IrKind::BuiltinAttr),
        tag => Err(format!("invalid IR kind tag {tag}")),
    }
}

fn decode_ir_dialect_op(raw: u32) -> Result<IrDialectOp, String> {
    let raw = u16::try_from(raw).map_err(|_| format!("invalid dialect op key {raw}"))?;
    Ok(IrDialectOp::new(raw))
}

pub(super) fn effect_class_tag(effect: EffectClass) -> u8 {
    effect.effect_key()
}

pub(super) fn decode_effect_class(tag: u8) -> Result<EffectClass, String> {
    Ok(EffectClass::from_cache_key(tag))
}

pub(super) fn node_kind_tag(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Int => 0,
        NodeKind::Float => 1,
        NodeKind::Str => 2,
        NodeKind::Path => 3,
        NodeKind::SearchPath => 4,
        NodeKind::Uri => 5,
        NodeKind::Ident => 6,
        NodeKind::List => 7,
        NodeKind::AttrSet => 8,
        NodeKind::RecAttrSet => 9,
        NodeKind::Lambda => 10,
        NodeKind::FormalSet => 11,
        NodeKind::Formal => 12,
        NodeKind::Apply => 13,
        NodeKind::Select => 14,
        NodeKind::HasAttr => 15,
        NodeKind::LetIn => 16,
        NodeKind::Binding => 17,
        NodeKind::With => 18,
        NodeKind::Assert => 19,
        NodeKind::IfThenElse => 20,
        NodeKind::BinOp => 21,
        NodeKind::UnaryOp => 22,
        NodeKind::Inherit => 23,
        NodeKind::Interp => 24,
        NodeKind::AttrPath => 25,
        NodeKind::LocalVar => 26,
        NodeKind::UpvalVar => 27,
        NodeKind::GlobalVar => 28,
        NodeKind::WithVar => 29,
    }
}

pub(super) fn decode_node_kind(tag: u8) -> Result<NodeKind, String> {
    match tag {
        0 => Ok(NodeKind::Int),
        1 => Ok(NodeKind::Float),
        2 => Ok(NodeKind::Str),
        3 => Ok(NodeKind::Path),
        4 => Ok(NodeKind::SearchPath),
        5 => Ok(NodeKind::Uri),
        6 => Ok(NodeKind::Ident),
        7 => Ok(NodeKind::List),
        8 => Ok(NodeKind::AttrSet),
        9 => Ok(NodeKind::RecAttrSet),
        10 => Ok(NodeKind::Lambda),
        11 => Ok(NodeKind::FormalSet),
        12 => Ok(NodeKind::Formal),
        13 => Ok(NodeKind::Apply),
        14 => Ok(NodeKind::Select),
        15 => Ok(NodeKind::HasAttr),
        16 => Ok(NodeKind::LetIn),
        17 => Ok(NodeKind::Binding),
        18 => Ok(NodeKind::With),
        19 => Ok(NodeKind::Assert),
        20 => Ok(NodeKind::IfThenElse),
        21 => Ok(NodeKind::BinOp),
        22 => Ok(NodeKind::UnaryOp),
        23 => Ok(NodeKind::Inherit),
        24 => Ok(NodeKind::Interp),
        25 => Ok(NodeKind::AttrPath),
        26 => Ok(NodeKind::LocalVar),
        27 => Ok(NodeKind::UpvalVar),
        28 => Ok(NodeKind::GlobalVar),
        29 => Ok(NodeKind::WithVar),
        tag => Err(format!("invalid node kind tag {tag}")),
    }
}

pub(super) fn bin_op_tag(op: BinOpKind) -> u8 {
    match op {
        BinOpKind::Add => 0,
        BinOpKind::Sub => 1,
        BinOpKind::Mul => 2,
        BinOpKind::Div => 3,
        BinOpKind::Concat => 4,
        BinOpKind::Update => 5,
        BinOpKind::Lt => 6,
        BinOpKind::Gt => 7,
        BinOpKind::Le => 8,
        BinOpKind::Ge => 9,
        BinOpKind::Eq => 10,
        BinOpKind::Ne => 11,
        BinOpKind::And => 12,
        BinOpKind::Or => 13,
        BinOpKind::Impl => 14,
        BinOpKind::PipeRight => 15,
        BinOpKind::PipeLeft => 16,
    }
}

pub(super) fn decode_bin_op(tag: u8) -> Result<BinOpKind, String> {
    match tag {
        0 => Ok(BinOpKind::Add),
        1 => Ok(BinOpKind::Sub),
        2 => Ok(BinOpKind::Mul),
        3 => Ok(BinOpKind::Div),
        4 => Ok(BinOpKind::Concat),
        5 => Ok(BinOpKind::Update),
        6 => Ok(BinOpKind::Lt),
        7 => Ok(BinOpKind::Gt),
        8 => Ok(BinOpKind::Le),
        9 => Ok(BinOpKind::Ge),
        10 => Ok(BinOpKind::Eq),
        11 => Ok(BinOpKind::Ne),
        12 => Ok(BinOpKind::And),
        13 => Ok(BinOpKind::Or),
        14 => Ok(BinOpKind::Impl),
        15 => Ok(BinOpKind::PipeRight),
        16 => Ok(BinOpKind::PipeLeft),
        tag => Err(format!("invalid binary operator tag {tag}")),
    }
}

pub(super) fn unary_op_tag(op: UnaryOpKind) -> u8 {
    match op {
        UnaryOpKind::Neg => 0,
        UnaryOpKind::Not => 1,
    }
}

pub(super) fn decode_unary_op(tag: u8) -> Result<UnaryOpKind, String> {
    match tag {
        0 => Ok(UnaryOpKind::Neg),
        1 => Ok(UnaryOpKind::Not),
        tag => Err(format!("invalid unary operator tag {tag}")),
    }
}

pub(super) struct BinaryReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> BinaryReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn expect_magic(&mut self, magic: &[u8]) -> Result<(), String> {
        let actual = self.read_bytes(magic.len())?;
        if actual == magic {
            Ok(())
        } else {
            Err("invalid artifact magic".to_owned())
        }
    }

    pub(super) fn expect_eof(&self) -> Result<(), String> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err("trailing bytes in artifact".to_owned())
        }
    }

    pub(super) fn is_eof(&self) -> bool {
        self.cursor == self.bytes.len()
    }

    pub(super) fn read_len(&mut self, what: &'static str) -> Result<usize, String> {
        usize::try_from(self.read_u32()?).map_err(|_| format!("{what} does not fit usize"))
    }

    pub(super) fn read_option_u32(&mut self) -> Result<Option<u32>, String> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u32()?)),
            tag => Err(format!("invalid option tag {tag}")),
        }
    }

    pub(super) fn read_option_span(&mut self) -> Result<Option<Span>, String> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(Span::new(self.read_u32()?, self.read_u32()?))),
            tag => Err(format!("invalid option tag {tag}")),
        }
    }

    pub(super) fn read_bool(&mut self) -> Result<bool, String> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(format!("invalid bool tag {tag}")),
        }
    }

    pub(super) fn read_u8(&mut self) -> Result<u8, String> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub(super) fn read_u16(&mut self) -> Result<u16, String> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, String> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub(super) fn read_i64(&mut self) -> Result<i64, String> {
        let bytes = self.read_array::<8>()?;
        Ok(i64::from_le_bytes(bytes))
    }

    pub(super) fn read_f64(&mut self) -> Result<f64, String> {
        let bytes = self.read_array::<8>()?;
        Ok(f64::from_le_bytes(bytes))
    }

    pub(super) fn read_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let bytes = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    pub(super) fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| "artifact cursor overflow".to_owned())?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| "unexpected end of artifact".to_owned())?;
        self.cursor = end;
        Ok(bytes)
    }
}
