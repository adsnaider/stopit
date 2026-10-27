//! Crate-level error types shared by value parsers, and helpers for
//! classifying I/O errors.

use std::io;

use thiserror::Error;

/// Error parsing a custom value type. The message quotes the offending value
/// with `{:?}` and says why it was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct ValueError(String);

impl ValueError {
    /// Creates an error with the given message.
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        ValueError(msg.into())
    }
}

/// Whether an error inspecting a path means it is missing: it, or a
/// component on the way, does not exist or is not a directory. A missing
/// path skips a rule with a warning whatever its mode (DESIGN.md §3.4,
/// Symlinks); any other error (`EACCES`, `ELOOP`) means the path exists but
/// cannot be inspected.
pub(crate) fn is_missing(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
}
