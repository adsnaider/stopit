//! stopit is a Linux sandbox tool that runs commands with restricted access to
//! the filesystem, network and other host resources. See `DESIGN.md` at the
//! repository root for the full design.

pub mod config;
pub mod policy;

/// The version of the `stopit` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
