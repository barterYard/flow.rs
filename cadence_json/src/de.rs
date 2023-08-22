use std::num::Wrapping;

use serde::de::{DeserializeSeed, Error, Visitor};
use serde::Deserializer;
use serde_json::json;

use super::wrapper::*;
use crate::ValueOwned;

struct ExpectedStr(&'static str);

impl<'de> Visitor<'de> for ExpectedStr {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "A string \"{}\"", self.0)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v != self.0 {
            Err(E::custom("invalid string"))
        } else {
            Ok(())
        }
    }
}

impl<'de> DeserializeSeed<'de> for ExpectedStr {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(self)
    }
}

struct StrMap<F: FnOnce(&str) -> Result<R, E>, R, E>(F);

impl<'de, F: FnOnce(&str) -> Result<R, E>, R, E: Error> DeserializeSeed<'de> for StrMap<F, R, E> {
    type Value = R;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(self)
    }
}

impl<'de, F: FnOnce(&str) -> Result<R, E>, R, E: Error> Visitor<'de> for StrMap<F, R, E> {
    type Value = R;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a cadence type string")
    }

    fn visit_str<E1>(self, v: &str) -> Result<Self::Value, E1>
    where
        E1: Error,
    {
        self.0(v).map_err(E1::custom)
    }
}

struct CadenceObjectVisitor;

impl<'de> Visitor<'de> for CadenceObjectVisitor {
    type Value = ValueOwned;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "A Cadence-JSON Object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        use crate::Type::*;

        let mut ty: super::Type = super::Type::Void;
        let mut val: serde_json::Value = json!({});
        while let Ok(Some(k)) = map.next_key::<std::string::String>() {
            if k == "type" {
                ty = map.next_value()?;
                if ty == super::Type::Void {
                    return Ok(ValueOwned::Void);
                }
            } else {
                val = map.next_value()?;
            }
        }

        Ok(match ty {
            Void => ValueOwned::Void,
            Optional => ValueOwned::Optional(serde_json::from_value(val).expect("error parsing")),
            Bool => ValueOwned::Bool(serde_json::from_value(val).expect("error parsing")),
            String => ValueOwned::String(serde_json::from_value(val).expect("error parsing")),
            Address => ValueOwned::Address(serde_json::from_value(val).expect("error parsing")),
            UInt => ValueOwned::UInt(
                serde_json::from_value::<BigUint>(val)
                    .expect("error parsing")
                    .0,
            ),
            UInt8 => ValueOwned::UInt8(serde_json::from_value::<U8>(val).expect("error parsing").0),
            UInt16 => {
                ValueOwned::UInt16(serde_json::from_value::<U16>(val).expect("error parsing").0)
            }
            UInt32 => {
                ValueOwned::UInt32(serde_json::from_value::<U32>(val).expect("error parsing").0)
            }
            UInt64 => {
                ValueOwned::UInt64(serde_json::from_value::<U64>(val).expect("error parsing").0)
            }
            UInt128 => ValueOwned::UInt128(
                serde_json::from_value::<U128>(val)
                    .expect("error parsing")
                    .0,
            ),
            UInt256 => ValueOwned::UInt256(
                serde_json::from_value::<BigUint>(val)
                    .expect("error parsing")
                    .0,
            ),
            Int => ValueOwned::Int(
                serde_json::from_value::<BigInt>(val)
                    .expect("error parsing")
                    .0,
            ),
            Int8 => ValueOwned::Int8(serde_json::from_value::<I8>(val).expect("error parsing").0),
            Int16 => {
                ValueOwned::Int16(serde_json::from_value::<I16>(val).expect("error parsing").0)
            }
            Int32 => {
                ValueOwned::Int32(serde_json::from_value::<I32>(val).expect("error parsing").0)
            }
            Int64 => {
                ValueOwned::Int64(serde_json::from_value::<I64>(val).expect("error parsing").0)
            }
            Int128 => ValueOwned::Int128(
                serde_json::from_value::<I128>(val)
                    .expect("error parsing")
                    .0,
            ),
            Int256 => ValueOwned::Int256(
                serde_json::from_value::<BigInt>(val)
                    .expect("error parsing")
                    .0,
            ),
            Word8 => ValueOwned::Word8(
                serde_json::from_value::<U8>(val)
                    .map(|n| n.0)
                    .map(Wrapping)
                    .expect("error parsing"),
            ),
            Word16 => ValueOwned::Word16(
                serde_json::from_value::<U16>(val)
                    .map(|n| n.0)
                    .map(Wrapping)
                    .expect("error parsing"),
            ),
            Word32 => ValueOwned::Word32(
                serde_json::from_value::<U32>(val)
                    .map(|n| n.0)
                    .map(Wrapping)
                    .expect("error parsing"),
            ),
            Word64 => ValueOwned::Word64(
                serde_json::from_value::<U64>(val)
                    .map(|n| n.0)
                    .map(Wrapping)
                    .expect("error parsing"),
            ),
            UFix64 => ValueOwned::UFix64(serde_json::from_value(val).expect("error parsing")),
            Fix64 => ValueOwned::Fix64(serde_json::from_value(val).expect("error parsing")),
            Array => ValueOwned::Array(serde_json::from_value(val).expect("error parsing")),
            Dictionary => {
                ValueOwned::Dictionary(serde_json::from_value(val).expect("error parsing"))
            }
            Struct => ValueOwned::Struct(serde_json::from_value(val).expect("error parsing")),
            Resource => ValueOwned::Resource(serde_json::from_value(val).expect("error parsing")),
            Event => ValueOwned::Event(serde_json::from_value(val).expect("error parsing")),
            Contract => ValueOwned::Contract(serde_json::from_value(val).expect("error parsing")),
            Enum => ValueOwned::Enum(serde_json::from_value(val).expect("error parsing")),
            Path => ValueOwned::Path(serde_json::from_value(val).expect("error parsing")),
            Type => ValueOwned::Type(
                serde_json::from_value::<TypeDe>(val)
                    .expect("error parsing")
                    .static_type,
            ),
            Capability => {
                ValueOwned::Capability(serde_json::from_value(val).expect("error parsing"))
            }
        })
    }
}

impl<'de> serde::Deserialize<'de> for super::ValueOwned {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CadenceObjectVisitor)
    }
}
