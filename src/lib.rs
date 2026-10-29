//! stopit is a Linux sandbox tool that runs commands with restricted access to
//! the filesystem, network and other host resources. See `DESIGN.md` at the
//! repository root for the full design.

pub mod approval;
pub mod bwrap;
pub mod cli;
pub mod config;
pub mod control;
mod env;
pub mod error;
pub mod escape;
pub mod etc;
pub mod expand;
pub mod filter;
pub mod init;
pub mod landlock;
pub mod manifest;
pub mod policy;
pub mod provider;
pub mod provision;
pub mod pty;
pub mod resolve;
pub mod seccomp;
mod serde_util;
pub mod server;
pub mod session;
pub mod spec;
pub mod state;
pub mod summary;
pub mod supervisor;
pub mod trust;

/// The version of the `stopit` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
