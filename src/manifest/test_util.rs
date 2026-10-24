//! Helpers shared by the manifest unit tests.

use super::Manifest;

pub(super) fn toml_ok(src: &str) -> Manifest {
    toml::from_str(src).unwrap_or_else(|e| panic!("{src:?}: {e}"))
}

pub(super) fn toml_err(src: &str) -> String {
    match toml::from_str::<Manifest>(src) {
        Ok(m) => panic!("expected an error for {src:?}, got {m:?}"),
        Err(e) => e.to_string(),
    }
}

pub(super) fn json_err(src: &str) -> String {
    match Manifest::from_json_str(src) {
        Ok(m) => panic!("expected an error for {src:?}, got {m:?}"),
        Err(e) => e.to_string(),
    }
}

/// Wraps JSON object members in an object that declares `version: 1`,
/// which `from_json_str` requires.
pub(super) fn jv(members: &str) -> String {
    if members.is_empty() {
        r#"{"version": 1}"#.to_owned()
    } else {
        format!(r#"{{"version": 1, {members}}}"#)
    }
}

pub(super) fn jv_ok(members: &str) -> Manifest {
    let src = jv(members);
    Manifest::from_json_str(&src).unwrap_or_else(|e| panic!("{src}: {e}"))
}

pub(super) fn jv_err(members: &str) -> String {
    json_err(&jv(members))
}
