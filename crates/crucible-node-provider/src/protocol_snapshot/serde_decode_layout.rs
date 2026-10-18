//! Names schema-neutral fixed controls of the pinned serde decoders.
//!
//! These are layout DATA. They do not parse, inspect a DTO, bound heap backing,
//! establish depth or grant constructor credit. Each caller keeps its actual
//! DTO field partials and independently admitted depth/heap/expansion/failure
//! rows. Versioned Content names deliberately make a serde upgrade re-audit it.

use serde_json::{Map, Value};
use std::borrow::Cow;
use std::mem::{align_of, size_of};

type Content = serde::__private228::de::Content<'static>;
type Error = serde_json::Error;
const PARSER_DEPTH: usize = 128;

/// Returns one actual pinned tagged-buffer Content slot's inline byte size.
pub const fn content_slot_bytes_data() -> usize {
    size_of::<Content>()
}

/// Returns one actual pinned tagged-buffer map pair's inline byte size.
pub const fn content_pair_bytes_data() -> usize {
    size_of::<(Content, Content)>()
}

/// Names owned Value adapters under an established 64-container profile.
///
/// An existing successful Value-only bounded walk must establish this profile
/// if earlier RawValue reparses could have expanded the supplied Value. The
/// walk starts at depth zero and accepts 64 containers followed by a scalar;
/// these are 65 actual visitor activations. This does not establish the profile
/// for a later expanded tree. The reparse companion independently prices any
/// additional reset parser work.
pub fn owned_value_counter_scratch_data() -> usize {
    65 * owned_value_frame_counter_scratch_data() + error_counter_scratch_data()
}

/// Names one actual owned-Value adapter activation without choosing depth.
///
/// A later typed pass over an expanded value must use its own proven reachable
/// depth rather than borrow the baseline64 profile. Heap/error message backing
/// and schema-specific partials remain separate.
pub fn owned_value_frame_counter_scratch_data() -> usize {
    type MapIterator = <Map<String, Value> as IntoIterator>::IntoIter;
    // Pinned value/de.rs Map={iter,value}; Seq={iter}; Enum={variant,value};
    // Variant={value}; MapKey={Cow<str>}. PhantomData fields occupy zero bytes.
    let map = pair_layout::<MapIterator, Option<Value>>();
    let sequence = field_layout::<std::vec::IntoIter<Value>>();
    let enumeration = pair_layout::<String, Option<Value>>();
    let variant = field_layout::<Option<Value>>();
    let map_key = field_layout::<Cow<'static, str>>();

    (map + sequence
        + enumeration
        + variant
        + map_key
        + size_of::<Value>()
        + size_of::<Option<Value>>()
        + size_of::<Result<Value, Error>>()
        + size_of::<Result<Option<Value>, Error>>()
        + size_of::<(String, Value)>()
        + size_of::<Option<(String, Value)>>()
        + size_of::<Result<Option<(String, Value)>, Error>>()
        + size_of::<String>()
        + size_of::<Option<String>>()
        + size_of::<&str>()
        + size_of::<usize>())
        + key_class_counter_scratch_data()
        + size_of::<serde_json::Number>()
        + size_of::<Result<serde_json::Number, Error>>()
        + 5 * size_of::<usize>() // the five actual layout calculation results
}

/// Names actual SliceRead/StrRead default128 text parser fixed controls.
///
/// from_str/from_slice start remaining_depth128 and do not disable recursion,
/// even when unbounded_depth is unified. The pinned check decrements before
/// refusing zero, admitting at most 127 containers plus a terminal scalar;
/// the existing 128 activation headers include that leaf. This is not a
/// physical process-stack
/// allowance. Caller DTO/Content partials and source/scratch/DOM/error backing
/// remain separate. These actual pinned field rosters are independently priced
/// here; no reparse row or unrelated phase credit is imported.
pub fn text_counter_scratch_data() -> usize {
    type Parser = serde_json::Deserializer<serde_json::de::StrRead<'static>>;
    type MapIterator = <Map<String, Value> as IntoIterator>::IntoIter;
    // Both actual text SeqAccess/MapAccess contain &mut Deserializer and bool.
    let access = pair_layout::<&mut Parser, bool>();
    // Owned Value::Deserializer can coexist when a Value visitor invokes the
    // nested text parser. Its concrete private map/sequence states are retained.
    let owned_map = pair_layout::<MapIterator, Option<Value>>();
    let owned_sequence = field_layout::<std::vec::IntoIter<Value>>();
    let owned_enum = pair_layout::<String, Option<Value>>();
    let owned_variant = field_layout::<Option<Value>>();
    let key_headers = key_class_counter_scratch_data();

    // Pinned de.rs ParserNumber={F64(f64),U64(u64),I64(i64),String(String)};
    // the final variant is feature-dependent, included as a layout upper only.
    // The enum and its Result are independent actual return/local headers.
    let number_alignment = align_of::<u64>()
        .max(align_of::<i64>())
        .max(align_of::<f64>())
        .max(align_of::<String>())
        .max(align_of::<usize>());
    let number_payload = size_of::<u64>()
        .max(size_of::<i64>())
        .max(size_of::<f64>())
        .max(size_of::<String>());
    let parser_number = tagged_layout_data(number_payload, number_alignment);
    let parser_number_result = tagged_layout_data(
        parser_number.max(size_of::<serde_json::Error>()),
        number_alignment,
    );

    // read::Reference<'a,'b,str>={Borrowed(&str),Copied(&str)} is private to
    // serde_json's read module. Name its tag/payload and independent Result.
    let text_reference = tagged_layout_data(size_of::<&str>(), align_of::<&str>());
    let text_reference_result = tagged_layout_data(
        text_reference.max(size_of::<serde_json::Error>()),
        align_of::<&str>(),
    );

    size_of::<Parser>().max(size_of::<serde_json::Deserializer<serde_json::de::SliceRead<'static>>>())
        + PARSER_DEPTH * (2 * access
            + size_of::<Value>() + size_of::<Option<Value>>()
            + size_of::<Vec<Value>>() + size_of::<Map<String,Value>>()
            + size_of::<String>() + size_of::<Option<String>>()
            + size_of::<Result<Value,serde_json::Error>>()
            + size_of::<Result<(),serde_json::Error>>()
            + size_of::<&mut Parser>() + size_of::<usize>()
            + key_headers
            + size_of::<Result<Option<Value>, serde_json::Error>>()
            + size_of::<(String, Value)>() + size_of::<Option<(String, Value)>>()
            + size_of::<Result<Option<(String, Value)>, serde_json::Error>>())
        + owned_map + owned_sequence + owned_enum + owned_variant
        + parser_number + parser_number_result
        + text_reference + text_reference_result
        + size_of::<Result<f64, serde_json::Error>>()
        + size_of::<Result<u64, serde_json::Error>>()
        + size_of::<Result<u16, serde_json::Error>>()
        + size_of::<Result<Option<u8>, serde_json::Error>>()
        + size_of::<Option<u8>>()
        + 2 * size_of::<usize>() // actual read::Position{line,column}
        + size_of::<Vec<u8>>()
        // RawValue is repr(transparent) over str. This names its real owned
        // String/Box<str> views without requiring raw_value to be enabled.
        + size_of::<Box<str>>() + size_of::<String>()
        + size_of::<&str>() + size_of::<std::str::Chars<'static>>()
        + size_of::<Option<char>>() + size_of::<[u16;2]>()
        + size_of::<Result<&str,std::str::Utf8Error>>()
        + size_of::<Result<f64,std::num::ParseFloatError>>()
        + size_of::<f64>() + size_of::<u64>() + size_of::<i64>()
        + error_counter_scratch_data()
        // Access/owned adapter/key/number/reference layout calculation results.
        + (1 + 4 + 1 + 4 + 2) * size_of::<usize>()
}

/// Names one actual serde private Content/owned/ref/tag-buffer activation.
///
/// The caller multiplies by its independently established reachable Content
/// depth and keeps its own DTO field partials and heap populations. Generated
/// visitor parameters are PhantomData-only; actual DTO field discriminants
/// remain the caller's defining row.
pub fn content_frame_counter_scratch_data() -> usize {
    use serde::__private228::de::{
        ContentDeserializer, ContentRefDeserializer, ContentVisitor, EnumDeserializer,
        TagContentOtherField, TagContentOtherFieldVisitor, TagOrContentField,
        TagOrContentFieldVisitor, TaggedContentVisitor,
    };

    // serde private/de.rs Seq/Map and SeqRef/MapRef: their PhantomData is ZST.
    let sequence = pair_layout::<std::vec::IntoIter<Content>, usize>();
    let map = triple_layout::<std::vec::IntoIter<(Content, Content)>, Option<Content>, usize>();
    let sequence_ref = pair_layout::<std::slice::Iter<'static, Content>, usize>();
    let map_ref =
        triple_layout::<std::slice::Iter<'static, (Content, Content)>, Option<&Content>, usize>();
    let pair = pair_layout::<Content, Content>();
    let pair_visitor = pair_layout::<Option<Content>, Option<Content>>();
    let pair_ref = pair_layout::<&Content, &Content>();
    let pair_ref_visitor = pair_layout::<Option<&Content>, Option<&Content>>();
    let enumeration_ref = pair_layout::<&Content, Option<&Content>>();
    let variant = field_layout::<Option<Content>>();
    let variant_ref = field_layout::<Option<&Content>>();
    // Private TagOrContent={Tag,Content(Content)} and visitor {name:&str}.
    let alignment = align_of::<Content>().max(align_of::<usize>());
    let tag = tagged_layout_data(size_of::<Content>(), alignment);
    let optional_tag = tagged_layout_data(tag, alignment);
    let tag_result = tagged_layout_data(tag.max(size_of::<Error>()), alignment);
    let optional_tag_result = tagged_layout_data(optional_tag.max(size_of::<Error>()), alignment);

    sequence
        + map
        + sequence_ref
        + map_ref
        + pair
        + pair_visitor
        + pair_ref
        + pair_ref_visitor
        + enumeration_ref
        + variant
        + variant_ref
        + tag
        + optional_tag
        + tag_result
        + optional_tag_result
        + field_layout::<&str>()
        + size_of::<Content>()
        + size_of::<Option<Content>>()
        + size_of::<Result<Content, Error>>()
        + size_of::<Result<Option<Content>, Error>>()
        + size_of::<(Content, Content)>()
        + size_of::<Option<(Content, Content)>>()
        + size_of::<Result<Option<(Content, Content)>, Error>>()
        + size_of::<Vec<Content>>()
        + size_of::<Vec<(Content, Content)>>()
        + size_of::<ContentVisitor<'static>>()
        + size_of::<ContentDeserializer<'static, Error>>()
        + size_of::<ContentRefDeserializer<'static, 'static, Error>>()
        + size_of::<EnumDeserializer<'static, Error>>()
        + size_of::<TaggedContentVisitor<u8>>()
        + size_of::<TagOrContentField>()
        + size_of::<TagOrContentFieldVisitor>()
        + size_of::<TagContentOtherField>()
        + size_of::<TagContentOtherFieldVisitor>()
        + size_of::<Result<(), Error>>()
        + size_of::<&str>()
        + 16 * size_of::<usize>() // the named calculation results above
}

fn triple_layout<A, B, C>() -> usize {
    let alignment = align_of::<A>().max(align_of::<B>()).max(align_of::<C>());
    size_of::<A>() + size_of::<B>() + size_of::<C>() + 4 * (alignment - 1)
}

// Exact pinned Content variants: an upgrade cannot silently add a branch.
const _: fn(&Content) = |value| match value {
    Content::Bool(_)
    | Content::U8(_)
    | Content::U16(_)
    | Content::U32(_)
    | Content::U64(_)
    | Content::I8(_)
    | Content::I16(_)
    | Content::I32(_)
    | Content::I64(_)
    | Content::F32(_)
    | Content::F64(_)
    | Content::Char(_)
    | Content::String(_)
    | Content::Str(_)
    | Content::ByteBuf(_)
    | Content::Bytes(_)
    | Content::None
    | Content::Some(_)
    | Content::Unit
    | Content::Newtype(_)
    | Content::Seq(_)
    | Content::Map(_) => {}
};

// Both Value::Deserializer and text Value visitors use this same actual
// KeyClass seed. It is independent of RawValue parsing and ordinary string
// maps require it even when the extra reparse row is zero.
fn key_class_counter_scratch_data() -> usize {
    // Pinned KeyClass={Map(String),Number,RawValue}; KeyClassifier is a ZST.
    let alignment = align_of::<String>().max(align_of::<usize>());
    let key = tagged_layout_data(size_of::<String>(), alignment);
    let optional = tagged_layout_data(key, alignment);
    let result = tagged_layout_data(key.max(size_of::<Error>()), alignment);
    let optional_result = tagged_layout_data(optional.max(size_of::<Error>()), alignment);
    key + optional + result + optional_result + 5 * size_of::<usize>()
}

fn error_counter_scratch_data() -> usize {
    // Names both old/new error and formatted/boxed message views while custom
    // converts the prior Error; parse_line_col has five indices + two results.
    2 * size_of::<serde_json::Error>()
        + 2 * size_of::<String>()
        + 2 * size_of::<Box<str>>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<std::fmt::Arguments<'static>>()
        + size_of::<std::fmt::Formatter<'static>>()
        + size_of::<serde::de::Unexpected<'static>>()
        + size_of::<&dyn serde::de::Expected>()
        // Pinned zmij::Buffer is [MaybeUninit<u8>;24]; serde_json uses it in
        // JsonUnexpected::Float without a directly accessible Provider API.
        + size_of::<[std::mem::MaybeUninit<u8>; 24]>()
        // Core Display's u64/i64/usize decimal buffer on the selected64-bit
        // toolchain (also20 in its optimize_for_size implementation).
        + size_of::<[std::mem::MaybeUninit<u8>; 20]>()
        + size_of::<Result<usize, std::num::ParseIntError>>()
        + size_of::<Option<(usize, usize)>>()
        + size_of::<&str>()
        + 7 * size_of::<usize>()
}

fn field_layout<T>() -> usize {
    size_of::<T>() + align_of::<T>() - 1
}

fn pair_layout<A, B>() -> usize {
    size_of::<A>() + align_of::<A>() - 1 + size_of::<B>() + align_of::<B>() - 1
        + align_of::<A>().max(align_of::<B>())
        - 1
}

fn tagged_layout_data(payload: usize, alignment: usize) -> usize {
    // All named enums have at most four variants. A usize tag dominates the
    // discriminant; one payload/tag boundary and one final tail may each pad.
    payload + size_of::<usize>() + 2 * (alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::service::PacketNative5CaptureProfile;
    use crucible_node_contract::U64;
    use serde::Deserialize;
    use serde::de::DeserializeSeed;

    #[test]
    fn actual_tagged_profile_decodes_through_owned_and_borrowed_content() {
        use serde::__private228::de::{
            ContentDeserializer, ContentRefDeserializer, ContentVisitor,
        };

        let profile = PacketNative5CaptureProfile::OwnedProtocol11 {
            native_before_protocol_bytes: U64::new(1024),
            native_after_protocol_bytes: U64::new(2048),
            host_protocol_bytes: U64::new(4096),
        };
        let body = serde_json::to_value(&profile).unwrap();
        let content = ContentVisitor::new().deserialize(body).unwrap();
        let borrowed = PacketNative5CaptureProfile::deserialize(
            ContentRefDeserializer::<Error>::new(&content),
        )
        .unwrap();
        let owned =
            PacketNative5CaptureProfile::deserialize(ContentDeserializer::<Error>::new(content))
                .unwrap();
        assert_eq!(borrowed, profile);
        assert_eq!(owned, profile);
        assert!(content_frame_counter_scratch_data() > content_pair_bytes_data());
    }

    #[test]
    fn real_text_profiles_keep_slice_and_string_semantics_equal() {
        let bytes =
            br#"{"many":[null,true,-1,18446744073709551615,1.25],"text":"a\n\uD834\uDD1E"}"#;
        let slice: Value = serde_json::from_slice(bytes).unwrap();
        let text: Value = serde_json::from_str(std::str::from_utf8(bytes).unwrap()).unwrap();
        assert_eq!(slice, text);
        assert!(text_counter_scratch_data() > size_of::<Value>());
        assert!(owned_value_counter_scratch_data() > size_of::<Map<String, Value>>());
    }

    #[test]
    fn actual_value_credit_allows_64_containers_and_a_terminal_scalar() {
        use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;

        let mut value = Value::Null;
        for _ in 0..64 {
            value = Value::Array(vec![value]);
        }

        assert!(actual_serialization_storage_data(&value, Default::default(), usize::MAX).is_ok());
        assert_eq!(
            serde_json::from_value::<Value>(value.clone()).unwrap(),
            value
        );

        let too_deep = Value::Array(vec![value]);
        assert!(
            actual_serialization_storage_data(&too_deep, Default::default(), usize::MAX).is_err()
        );
    }

    #[test]
    fn actual_default_text_parser_allows_127_containers_and_a_terminal_scalar() {
        let admitted = format!("{}null{}", "[".repeat(127), "]".repeat(127));
        assert!(serde_json::from_str::<Value>(&admitted).is_ok());
        assert!(serde_json::from_slice::<Value>(admitted.as_bytes()).is_ok());

        let refused = format!("[{admitted}]");
        assert!(serde_json::from_str::<Value>(&refused).is_err());
        assert!(serde_json::from_slice::<Value>(refused.as_bytes()).is_err());
    }
}
