//! Tree-walk test support: `+` operator coercion matrix fixtures.

use super::super::*;
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddMatrixKind {
    Int,
    Float,
    String,
    Path,
    Bool,
    Null,
    List,
    PlainAttrs,
    ToStringAttrs,
    OutPathAttrs,
    Lambda,
    Primop,
}

#[derive(Debug)]
pub(crate) struct AddMatrixOperand {
    pub(crate) kind: AddMatrixKind,
    pub(crate) source: String,
}

pub(crate) fn add_operator_matrix_operands(prefix: &str) -> (PathBuf, Vec<AddMatrixOperand>) {
    let dir = unique_temp_dir(prefix);
    let path = dir.join("matrix.txt");
    fs::write(&path, b"matrix").expect("matrix path writes");
    let path = path_source(&path);
    let operands = vec![
        AddMatrixOperand {
            kind: AddMatrixKind::Int,
            source: "1".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Float,
            source: "1.5".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::String,
            source: r#""s""#.to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Path,
            source: path,
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Bool,
            source: "true".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Null,
            source: "null".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::List,
            source: "[ 1 ]".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::PlainAttrs,
            source: "{ a = 1; }".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::ToStringAttrs,
            source: r#"{ __toString = self: "attrs"; }"#.to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::OutPathAttrs,
            source: r#"{ outPath = "out"; }"#.to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Lambda,
            source: "x: x".to_owned(),
        },
        AddMatrixOperand {
            kind: AddMatrixKind::Primop,
            source: "builtins.length".to_owned(),
        },
    ];
    (dir, operands)
}

pub(crate) fn add_operator_matrix_source(
    left: &AddMatrixOperand,
    right: &AddMatrixOperand,
) -> String {
    format!("builtins.seq (({}) + ({})) true", left.source, right.source)
}

pub(crate) fn add_operator_matrix_kind_is_string_coercible(kind: AddMatrixKind) -> bool {
    matches!(
        kind,
        AddMatrixKind::String
            | AddMatrixKind::Path
            | AddMatrixKind::ToStringAttrs
            | AddMatrixKind::OutPathAttrs
    )
}

pub(crate) fn add_operator_matrix_cell_is_legal(left: AddMatrixKind, right: AddMatrixKind) -> bool {
    matches!(
        (left, right),
        (
            AddMatrixKind::Int | AddMatrixKind::Float,
            AddMatrixKind::Int | AddMatrixKind::Float
        )
    ) || (matches!(
        left,
        AddMatrixKind::String
            | AddMatrixKind::Path
            | AddMatrixKind::ToStringAttrs
            | AddMatrixKind::OutPathAttrs
    ) && add_operator_matrix_kind_is_string_coercible(right))
}
