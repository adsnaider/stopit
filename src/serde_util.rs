//! Small serde helpers shared by the configuration and manifest types.

use std::fmt;
use std::marker::PhantomData;

use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};

/// Deserializes `T` from a map only.
///
/// Serde-derived structs also accept sequences, matching fields by
/// declaration order (`[]`, `[["/a"]]`). In a security configuration the
/// meaning of a value must never depend on field order, so schema structs
/// are deserialized through this wrapper, which rejects everything but a
/// map (a JSON object or a TOML table).
pub(crate) struct MapOnly<T>(pub T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = MapOnly<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map (table or object)")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<MapOnly<T>, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }

        // Only `visit_map` is implemented, so any other shape yields
        // `invalid type: …, expected a map (table or object)`.
        deserializer.deserialize_map(V(PhantomData))
    }
}
