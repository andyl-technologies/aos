//! Encodes scalar/container fields and delegates literal trees to the real codec.

use super::*;
use crate::source_birth::literal_value::{self, StreamLimits};
use crucible_node_format::{Bytes, Id, U64};
use serde_json::Value;
use std::collections::BTreeMap;

macro_rules! integer {
    ($ty:ty, $n:expr) => {
        impl Retire for $ty {
            fn retire(&mut self) {}
        }

        impl Wire for $ty {
            fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
                out.item()?;
                out.write_all(&self.to_be_bytes())?;
                Ok(())
            }

            fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
                input.item()?;
                let mut bytes = [0; $n];
                input.read_exact(&mut bytes)?;
                Ok(Owned::new(Self::from_be_bytes(bytes)))
            }
        }
    };
}

integer!(u8, 1);
integer!(u16, 2);
integer!(u64, 8);

impl Retire for U64 {
    fn retire(&mut self) {}
}

impl Wire for U64 {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        out.item()?;
        out.write_all(&self.get().to_be_bytes())?;
        Ok(())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        Ok(Owned::new(Self::new(u64::decode(input)?.into_inner())))
    }
}

impl Retire for String {
    fn retire(&mut self) {}
}

impl Wire for String {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        out.item()?;
        out.raw(self.as_bytes())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        input.item()?;
        let bytes = input.raw()?;
        Ok(Owned::new(
            String::from_utf8(bytes).map_err(|_| ProtocolFault::Text)?,
        ))
    }
}

impl Retire for Id {
    fn retire(&mut self) {}
}

impl Wire for Id {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        out.item()?;
        out.raw(self.as_str().as_bytes())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        let text = String::decode(input)?.into_inner();
        Ok(Owned::new(
            Self::try_from_owned(text).map_err(|_| ProtocolFault::Text)?,
        ))
    }
}

impl Retire for Bytes {
    fn retire(&mut self) {}
}

impl Wire for Bytes {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        out.item()?;
        out.raw(self.as_slice())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        input.item()?;
        Ok(Owned::new(Self::new(input.raw()?)))
    }
}

impl<T: Wire> Wire for Option<T> {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        out.item()?;
        match self {
            None => out.write_all(&[0])?,
            Some(value) => {
                out.write_all(&[1])?;
                value.encode(out)?;
            }
        }
        Ok(())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        input.item()?;
        let mut tag = [0];
        input.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(Owned::new(None)),
            1 => Ok(Owned::new(Some(T::decode(input)?.into_inner()))),
            _ => Err(ProtocolFault::Edition.into()),
        }
    }
}

impl<T: Wire> Wire for Vec<T> {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        out.item()?;
        if self.len() > out.remaining_work() || self.len() > out.remaining_bytes() {
            return Err(ProtocolFault::Limit.into());
        }
        out.length(self.len())?;
        for value in self {
            value.encode(out)?;
        }
        Ok(())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        input.item()?;
        let count = input.length()?;
        if count > input.remaining_work() || count > input.remaining {
            return Err(ProtocolFault::Limit.into());
        }
        let mut out = Owned::new(Vec::new());
        out.get_mut().try_reserve_exact(count)?;
        for _ in 0..count {
            let value = T::decode(input)?;
            out.get_mut().push(value.into_inner());
        }
        Ok(out)
    }
}

impl<T: Wire> Wire for BTreeMap<String, T> {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        out.item()?;
        if self.len() > out.remaining_work() || self.len() > out.remaining_bytes() {
            return Err(ProtocolFault::Limit.into());
        }
        out.length(self.len())?;
        for (key, value) in self {
            key.encode(out)?;
            value.encode(out)?;
        }
        Ok(())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        input.item()?;
        let count = input.length()?;
        if count > input.remaining_work() || count > input.remaining {
            return Err(ProtocolFault::Limit.into());
        }
        let mut out = Owned::new(BTreeMap::new());
        for _ in 0..count {
            let key = String::decode(input)?;
            if out
                .get()
                .last_key_value()
                .is_some_and(|(old, _)| old >= key.get())
            {
                return Err(ProtocolFault::MapOrder.into());
            }
            let value = T::decode(input)?;
            out.get_mut().insert(key.into_inner(), value.into_inner());
        }
        Ok(out)
    }
}

impl Wire for Value {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError> {
        let limits = StreamLimits {
            maximum_wire_bytes: out.remaining_bytes(),
            maximum_values: out.remaining_work() / 2,
        };
        let mut workspace = std::mem::replace(
            &mut out.workspace,
            literal_value::LiteralWriteWorkspace::new(0)?,
        );
        let result = literal_value::write_value_in(self, &mut *out, limits, &mut workspace);
        out.workspace = workspace;
        let statistics = result?;
        out.charge(statistics.values)?;
        out.charge(statistics.values)?;
        Ok(())
    }

    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError> {
        let limits = StreamLimits {
            maximum_wire_bytes: input.remaining,
            maximum_values: input.remaining_work() / 2,
        };
        let literal =
            literal_value::read_value(&mut *input, limits).map_err(CodecError::LiteralRead)?;
        input.charge(literal.statistics().values)?;
        value_clone::clone_inside_child(literal.value()?, input)
    }
}
