//! Defines closed wire records with an object-only deserialization entry point.
//!
//! Serde's ordinary struct derive also accepts positional sequences when its
//! input is an owned or borrowed `Value`. Requiring a map at each record keeps
//! the wire rule intact after an internally tagged enum buffers its contents.

/// Defines a closed named-field record that deserializes only from an object.
///
/// The declaration supplies one field roster for the public record and its
/// private derived field decoder. Field attributes, including custom decoders,
/// defaults and renames, apply to both. The outer visitor borrows the original
/// map access; it creates no intermediate JSON tree or serialized byte bank.
/// Unknown fields remain errors. Scalar newtypes and literal JSON arrays do
/// not use this macro.
///
/// Supply documentation and ordinary derives as item attributes; omit
/// `Deserialize` and container-level serde attributes. The macro supplies the
/// object-only `Deserialize` implementation and `deny_unknown_fields` policy.
/// The invoking crate must depend on `serde` with its derive feature enabled.
///
/// # Examples
///
/// ```rust
/// crucible_node_format::wire_record! {
///     /// Identifies a wire label.
///     #[derive(Debug, PartialEq, serde::Serialize)]
///     pub struct Label {
///         /// Contains its text.
///         pub text: String,
///     }
/// }
///
/// let label: Label = serde_json::from_str(r#"{"text":"label"}"#)?;
/// assert_eq!(label.text, "label");
/// assert!(serde_json::from_value::<Label>(serde_json::json!(["label"])).is_err());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[macro_export]
macro_rules! wire_record {
    (
        $(#[$attribute:meta])*
        $visibility:vis struct $name:ident {
            $(
                $(#[$field_attribute:meta])*
                $field_visibility:vis $field:ident: $field_type:ty,
            )*
        }
    ) => {
        $(#[$attribute])*
        #[serde(deny_unknown_fields)]
        $visibility struct $name {
            $(
                $(#[$field_attribute])*
                $field_visibility $field: $field_type,
            )*
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::std::result::Result<Self, D::Error> {
                #[derive(::serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields {
                    $(
                        $(#[$field_attribute])*
                        $field: $field_type,
                    )*
                }

                struct ObjectVisitor;

                impl<'de> ::serde::de::Visitor<'de> for ObjectVisitor {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        formatter.write_str(concat!(stringify!($name), " object"))
                    }

                    fn visit_map<A: ::serde::de::MapAccess<'de>>(
                        self,
                        access: A,
                    ) -> ::std::result::Result<Self::Value, A::Error> {
                        let fields = <Fields as ::serde::Deserialize>::deserialize(
                            ::serde::de::value::MapAccessDeserializer::new(access),
                        )?;
                        Ok($name { $($field: fields.$field,)* })
                    }
                }

                deserializer.deserialize_map(ObjectVisitor)
            }
        }
    };
}

#[cfg(test)]
mod tests;
