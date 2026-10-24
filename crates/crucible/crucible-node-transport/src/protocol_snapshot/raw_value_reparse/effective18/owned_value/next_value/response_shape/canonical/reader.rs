//! Lends actual first/next nodes to one canonical walker without another pass.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum Node<'a> {
    First(SourceView<'a>),
    Next(NativeImport18NextValuePassViewData<'a>),
}

pub(super) enum Kind<'a> {
    Null,
    Bool(bool),
    Number(&'a Number),
    String(&'a str),
    Array(Array<'a>),
    Object(Object<'a>),
}

pub(super) enum Array<'a> {
    First(SourceArray<'a>),
    Next(NativeImport18NextValuePassArrayData<'a>),
}

pub(super) enum Object<'a> {
    First(SourceObject<'a>),
    Next(NativeImport18NextValuePassObjectData<'a>),
}

impl<'a> Node<'a> {
    pub(super) fn kind_data(self) -> Result<Kind<'a>, ProviderError> {
        Ok(match self {
            Self::First(value) => match value.kind_data()? {
                SourceKind::Null => Kind::Null,
                SourceKind::Bool(value) => Kind::Bool(value),
                SourceKind::Number(value) => Kind::Number(value),
                SourceKind::String(value) => Kind::String(value),
                SourceKind::Array(values) => Kind::Array(Array::First(values)),
                SourceKind::Object(values) => Kind::Object(Object::First(values)),
            },
            Self::Next(value) => match value.kind_data()? {
                NativeImport18NextValuePassKindData::Null => Kind::Null,
                NativeImport18NextValuePassKindData::Bool(value) => Kind::Bool(value),
                NativeImport18NextValuePassKindData::Number(value) => Kind::Number(value),
                NativeImport18NextValuePassKindData::String(value) => Kind::String(value),
                NativeImport18NextValuePassKindData::Array(values) => {
                    Kind::Array(Array::Next(values))
                }
                NativeImport18NextValuePassKindData::Object(values) => {
                    Kind::Object(Object::Next(values))
                }
            },
        })
    }
}

impl<'a> Iterator for Array<'a> {
    type Item = Node<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(values) => values.next().map(Node::First),
            Self::Next(values) => values.next().map(Node::Next),
        }
    }
}

impl<'a> Iterator for Object<'a> {
    type Item = (&'a str, Node<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(values) => values.next().map(|(key, value)| (key, Node::First(value))),
            Self::Next(values) => values.next().map(|(key, value)| (key, Node::Next(value))),
        }
    }
}

pub(super) fn counter_data() -> usize {
    size_of::<Node<'static>>() * 2
        + size_of::<Kind<'static>>()
        + size_of::<Result<Kind<'static>,ProviderError>>()
        + size_of::<Array<'static>>()
        + size_of::<Object<'static>>()
        + size_of::<&mut Array<'static>>()
        + size_of::<&mut Object<'static>>()
        + size_of::<SourceView<'static>>()
        + size_of::<NativeImport18NextValuePassViewData<'static>>()
        + size_of::<Option<SourceView<'static>>>()
        + size_of::<Option<NativeImport18NextValuePassViewData<'static>>>()
        + size_of::<SourceKind<'static>>()
        + size_of::<NativeImport18NextValuePassKindData<'static>>()
        + size_of::<Result<SourceKind<'static>,ProviderError>>()
        + size_of::<Result<NativeImport18NextValuePassKindData<'static>,ProviderError>>()
        + size_of::<SourceArray<'static>>()
        + size_of::<SourceObject<'static>>()
        + size_of::<NativeImport18NextValuePassArrayData<'static>>()
        + size_of::<NativeImport18NextValuePassObjectData<'static>>()
        + size_of::<&mut SourceArray<'static>>()
        + size_of::<&mut SourceObject<'static>>()
        + size_of::<&mut NativeImport18NextValuePassArrayData<'static>>()
        + size_of::<&mut NativeImport18NextValuePassObjectData<'static>>()
        + size_of::<(&str,SourceView<'static>)>()
        + size_of::<Option<(&str,SourceView<'static>)>>()
        + size_of::<(&str,NativeImport18NextValuePassViewData<'static>)>()
        + size_of::<Option<(&str,NativeImport18NextValuePassViewData<'static>)>>()
        + size_of::<Option<Node<'static>>>()
        + size_of::<(&str,Node<'static>)>()
        + size_of::<Option<(&str,Node<'static>)>>()
        + size_of::<&str>() * 2
        // These are different actual readers, with different final-boundary
        // controls. The NEXT projection receives its own defining roster.
        + super::super::super::view::counter_scratch_data()
        + super::super::super::input::counter_scratch_data()
}
