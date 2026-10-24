//! Crate-level error types shared by value parsers.

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
